import 'dotenv/config'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { PrismaClient } from '../generated/prisma/client.ts'
import { Google, generateCodeVerifier, generateState } from 'arctic'
import { SignJWT, jwtVerify } from 'jose'
import pg from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'
import { serve } from '@hono/node-server'
import { secureHeaders } from 'hono/secure-headers'
import { z } from 'zod'
import { google as googleapis } from 'googleapis'

type Variables = {
  userId: string
}

const app = new Hono<{ Variables: Variables }>()
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })
const adapter = new PrismaPg(pool)
const prisma = new PrismaClient({ adapter })

// ─── Config ───────────────────────────────────────────────────────────────────
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!
const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET!)
const FRONTEND_URL = process.env.FRONTEND_URL ?? 'http://localhost:5173'

const BACKEND_URL = process.env.BACKEND_URL ?? 'http://localhost:3000'

const googleAuth = new Google(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  `${BACKEND_URL}/api/auth/callback/google`
)

// Google API Client Helpers
function getOAuth2Client(refreshToken?: string | null) {
  const oauth2Client = new googleapis.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    `${BACKEND_URL}/api/auth/callback/google`
  )

  if (refreshToken) {
    oauth2Client.setCredentials({ refresh_token: refreshToken })
  }

  return oauth2Client
}

// Google Sheets Config
const GOOGLE_SHEET_ID = process.env.GOOGLE_SHEET_ID?.replace(/^"|"$/g, '')
const GOOGLE_DRIVE_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID?.replace(/^"|"$/g, '')
const GOOGLE_SHEET_TEMPLATE_ID = process.env.GOOGLE_SHEET_TEMPLATE_ID?.replace(/^"|"$/g, '')
const GOOGLE_SERVICE_ACCOUNT_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL?.replace(/^"|"$/g, '')
const GOOGLE_PRIVATE_KEY = process.env.GOOGLE_PRIVATE_KEY
  ?.replace(/^"|"$/g, '')
  ?.replace(/\\n/g, '\n')

// Kita tidak lagi menggunakan Service Account JWT secara global
// Tapi kita simpan API instance-nya saja
const sheets = googleapis.sheets('v4')
const drive = googleapis.drive('v3')

async function createSheetForUser(userName: string, userEmail: string, refreshToken: string) {
  const auth = getOAuth2Client(refreshToken)

  try {
    console.log(`Starting spreadsheet creation for user: ${userEmail}`)
    
    let spreadsheetId: string | null = null;

    if (GOOGLE_SHEET_TEMPLATE_ID) {
      console.log(`Copying from template: ${GOOGLE_SHEET_TEMPLATE_ID}`)
      const copyResponse = await drive.files.copy({
        auth,
        fileId: GOOGLE_SHEET_TEMPLATE_ID,
        requestBody: {
          name: `Finance Manager - ${userName}`,
          // Kita tidak perlu folder ID jika ini di Drive user sendiri
        }
      });
      spreadsheetId = copyResponse.data.id || null;
    } else {
      const spreadsheet = await sheets.spreadsheets.create({
        auth,
        requestBody: {
          properties: {
            title: `Finance Manager - ${userName}`
          }
        }
      });
      spreadsheetId = spreadsheet.data.spreadsheetId || null;

      if (spreadsheetId) {
        await sheets.spreadsheets.values.update({
          auth,
          spreadsheetId: spreadsheetId,
          range: 'Sheet1!A1',
          valueInputOption: 'USER_ENTERED',
          requestBody: {
            values: [['Tanggal', 'Nama', 'Jumlah', 'Kategori', 'Metode']]
          }
        });
      }
    }

    console.log(`Spreadsheet ready on user's drive: ${spreadsheetId}`)
    return spreadsheetId
  } catch (error: any) {
    console.error('Error creating spreadsheet on user drive:', error.message)
    return null
  }
}

async function appendToSheet(spreadsheetId: string | null, refreshToken: string | null, data: any[]) {
  if (!spreadsheetId || !refreshToken) {
    console.warn('[Spreadsheet] Missing ID or Refresh Token. Skipping.')
    return
  }

  const auth = getOAuth2Client(refreshToken)

  try {
    const spreadsheet = await sheets.spreadsheets.get({
      auth,
      spreadsheetId: spreadsheetId,
    })
    
    const firstSheetName = spreadsheet.data.sheets?.[0]?.properties?.title || 'Sheet1'

    await sheets.spreadsheets.values.append({
      auth,
      spreadsheetId: spreadsheetId,
      range: `${firstSheetName}!A:E`,
      valueInputOption: 'USER_ENTERED',
      requestBody: {
        values: [data],
      }
    })
    console.log(`Successfully appended to User's Google Sheet ${spreadsheetId}`)
  } catch (error: any) {
    console.error('[Spreadsheet] Error appending:', error.message)
  }
}

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use('*', secureHeaders())

app.use(
  '/*',
  cors({
    origin: (origin) => {
      // Izinkan localhost untuk dev, dan domain spesifik untuk prod dari ENV
      const allowedOrigins = [
        FRONTEND_URL,
        'http://localhost:5173',
      ]
      
      if (!origin) return FRONTEND_URL
      // Izinkan localhost hanya jika bukan mode produksi (opsional, tapi lebih aman)
      if (allowedOrigins.includes(origin) || (origin.includes('localhost') && process.env.NODE_ENV !== 'production')) {
         return origin
      }
      return FRONTEND_URL
    },
    allowHeaders: ['Content-Type', 'Authorization', 'Cookie'],
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
  })
)

// Global Error Handler untuk menyembunyikan stack trace di produksi
app.onError((err, c) => {
  console.error(`[Global Error]: ${err.message}`, err.stack)
  
  const status = (err as any).status || 500
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal Server Error' 
    : err.message

  return c.json({ error: message }, status)
})

// ─── Rate Limiting ─────────────────────────────────────────────────────────────
const rateLimitMap = new Map<string, { count: number; lastReset: number }>()
const RATE_LIMIT_WINDOW = 60 * 1000 // 1 menit
const MAX_REQUESTS = 100 // 100 request per menit per IP

const rateLimitMiddleware = async (c: any, next: any) => {
  const ip = c.req.header('x-forwarded-for') || 'anonymous'
  const now = Date.now()
  const record = rateLimitMap.get(ip) || { count: 0, lastReset: now }

  if (now - record.lastReset > RATE_LIMIT_WINDOW) {
    record.count = 1
    record.lastReset = now
  } else {
    record.count++
  }

  rateLimitMap.set(ip, record)

  if (record.count > MAX_REQUESTS) {
    return c.json({ error: 'Too many requests, please try again later.' }, 429)
  }

  await next()
}

// ─── Zod Schemas ─────────────────────────────────────────────────────────────
const incomeSchema = z.object({
  month: z.coerce.number().min(1).max(12),
  year: z.coerce.number().min(2000).max(2100),
  salary: z.coerce.number().min(0),
  atmBalance: z.coerce.number().min(0),
})

const expenseSchema = z.object({
  month: z.coerce.number().min(1).max(12),
  year: z.coerce.number().min(2000).max(2100),
  name: z.string().min(1).max(100),
  amount: z.coerce.number().min(0),
})

const savingSchema = z.object({
  month: z.coerce.number().min(1).max(12),
  year: z.coerce.number().min(2000).max(2100),
  instrument: z.string().min(1).max(100),
  amount: z.coerce.number().min(0),
})

const otherFundSchema = z.object({
  month: z.coerce.number().min(1).max(12),
  year: z.coerce.number().min(2000).max(2100),
  name: z.string().min(1).max(100),
  amount: z.coerce.number().min(0),
})

const recentExpenseSchema = z.object({
  name: z.string().min(1).max(100),
  amount: z.coerce.number().min(0),
  category: z.string().min(1).max(50),
  paymentMethod: z.string().min(1).max(50),
  date: z.string().datetime(), // Format ISO string dari frontend
})

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get('/', (c) => c.text('Finance API is running!'))

/**
 * Public ping endpoint for uptime monitoring (e.g., UptimeRobot)
 */
app.get('/api/ping', (c) => c.json({ status: 'ok', timestamp: new Date().toISOString() }))

/**
 * Step 1: Redirect ke Google OAuth consent screen
 */
app.get('/api/auth/google', (c) => {
  const state = generateState()
  const codeVerifier = generateCodeVerifier()

  const url = googleAuth.createAuthorizationURL(state, codeVerifier, [
    'openid',
    'profile',
    'email',
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive.file'
  ])

  // Tambahkan prompt consent & access_type offline untuk mendapatkan refresh token
  url.searchParams.set('prompt', 'consent')
  url.searchParams.set('access_type', 'offline')

  // Simpan state & codeVerifier di cookie (httpOnly, 10 menit)
  setCookie(c, 'oauth_state', state, {
    httpOnly: true,
    maxAge: 600,
    path: '/',
    secure: true,
    sameSite: 'None',
  })
  setCookie(c, 'oauth_code_verifier', codeVerifier, {
    httpOnly: true,
    maxAge: 600,
    path: '/',
    secure: true,
    sameSite: 'None',
  })

  return c.redirect(url.toString())
})

// Gunakan rate limiting pada callback juga untuk mencegah brute force
app.get('/api/auth/callback/google', rateLimitMiddleware, async (c) => {
  const { code, state } = c.req.query()
  const storedState = getCookie(c, 'oauth_state')
  const storedVerifier = getCookie(c, 'oauth_code_verifier')

  // Validasi state supaya aman dari CSRF
  if (!code || !state || state !== storedState || !storedVerifier) {
    return c.json({ error: 'Invalid OAuth state' }, 400)
  }

  // Tukar authorization code dengan access token
  let tokens
  try {
    tokens = await googleAuth.validateAuthorizationCode(code, storedVerifier)
  } catch {
    return c.json({ error: 'Failed to exchange code for token' }, 400)
  }

  const refreshToken = tokens.refreshToken()

  // Ambil data user dari Google
  const googleRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${tokens.accessToken()}` },
  })

  if (!googleRes.ok) {
    return c.json({ error: 'Failed to fetch user info from Google' }, 500)
  }

  const googleUser = (await googleRes.json()) as {
    id: string
    email: string
    name: string
    picture: string
  }

  // Upsert user ke database
  let user = await prisma.user.upsert({
    where: { googleId: googleUser.id },
    update: {
      email: googleUser.email,
      name: googleUser.name,
      avatar: googleUser.picture,
      ...(refreshToken ? { refreshToken } : {}),
    },
    create: {
      email: googleUser.email,
      name: googleUser.name,
      avatar: googleUser.picture,
      googleId: googleUser.id,
      refreshToken,
    },
  })

  // Jika user belum punya googleSheetId, buatkan sekarang
  if (!user.googleSheetId && user.refreshToken) {
    const sheetId = await createSheetForUser(googleUser.name, googleUser.email, user.refreshToken)
    if (sheetId) {
      user = await prisma.user.update({
        where: { id: user.id },
        data: { googleSheetId: sheetId }
      })
    }
  }

  // Buat JWT session (berlaku 7 hari)
  const jwt = await new SignJWT({ sub: user.id, email: user.email })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('7d')
    .sign(JWT_SECRET)

  // Redirect ke frontend dengan token di URL
  // Frontend yang akan menyimpan token ini secara lokal (localStorage/cookie first-party)
  return c.redirect(`${FRONTEND_URL}/dashboard?token=${jwt}`)
})

/**
 * Middleware untuk mengecek User Authentication
 * Sekarang mendukung pengambilan token dari Authorization header (Bearer token)
 * selain dari Cookie, berguna untuk komunikasi API cross-domain
 */
const authMiddleware = async (c: any, next: any) => {
  let token = getCookie(c, 'session')
  
  // Jika tidak ada di cookie, cari di Authorization header
  if (!token) {
    const authHeader = c.req.header('Authorization')
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7)
    }
  }

  if (!token) return c.json({ error: 'Unauthorized' }, 401)

  try {
    const result = await jwtVerify(token, JWT_SECRET)
    c.set('userId', result.payload.sub as string)
    await next()
  } catch {
    return c.json({ error: 'Invalid session' }, 401)
  }
}

/**
 * GET /api/auth/me — return data user yang sedang login
 */
app.get('/api/auth/me', async (c) => {
  let token = getCookie(c, 'session')
  
  // Jika tidak ada di cookie, cari di Authorization header
  if (!token) {
    const authHeader = c.req.header('Authorization')
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7)
    }
  }

  if (!token) return c.json({ error: 'Unauthorized' }, 401)

  let payload
  try {
    const result = await jwtVerify(token, JWT_SECRET)
    payload = result.payload
  } catch {
    return c.json({ error: 'Invalid session' }, 401)
  }

  const user = await prisma.user.findUnique({
    where: { id: payload.sub as string },
    select: { id: true, name: true, email: true, avatar: true }, // Jangan kirim refreshToken atau googleSheetId yang tak perlu
  })

  if (!user) return c.json({ error: 'User not found' }, 404)

  return c.json(user)
})

/**
 * POST /api/auth/logout — hapus session cookie
 */
app.post('/api/auth/logout', (c) => {
  deleteCookie(c, 'session')
  return c.json({ success: true })
})

/**
 * GET /api/auth/google-sheet-url — return URL spreadsheet user
 */
app.get('/api/auth/google-sheet-url', authMiddleware, async (c) => {
  const userId = c.get('userId')
  let user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, googleSheetId: true, name: true, email: true, refreshToken: true }
  })

  if (!user) return c.json({ error: 'User not found' }, 404)

  // Jika belum ada sheetId, coba buatkan sekarang (On-demand)
  if (!user.googleSheetId && user.refreshToken) {
    console.log(`User ${user.email} requested sheet but doesn't have one. Creating now...`)
    const sheetId = await createSheetForUser(user.name || 'User', user.email, user.refreshToken)
    if (sheetId) {
      user = await prisma.user.update({
        where: { id: userId },
        data: { googleSheetId: sheetId },
        select: { id: true, googleSheetId: true, name: true, email: true, refreshToken: true }
      })
    } else {
      return c.json({ error: 'Gagal membuat spreadsheet otomatis. Pastikan izin Google Sheets sudah diberikan saat login.' }, 500)
    }
  }

  return c.json({ url: `https://docs.google.com/spreadsheets/d/${user.googleSheetId}` })
})

/**
 * POST /api/auth/google-sheet-id — simpan ID spreadsheet secara manual
 */
app.post('/api/auth/google-sheet-id', authMiddleware, async (c) => {
  const userId = c.get('userId')
  const { sheetId } = await c.req.json()

  if (!sheetId) return c.json({ error: 'ID Spreadsheet wajib diisi' }, 400)

  // Ekstrak ID jika user memasukkan full URL
  let finalId = sheetId
  const match = sheetId.match(/\/d\/([a-zA-Z0-9-_]+)/)
  if (match) finalId = match[1]

  await prisma.user.update({
    where: { id: userId },
    data: { googleSheetId: finalId }
  })

  return c.json({ success: true, sheetId: finalId })
})

// ─── Financial Records Routes ────────────────────────────────────────────────────────

// 1. Income (Data Gaji & sisa ATM)
app.get('/api/income', authMiddleware, async (c) => {
const userId = c.get('userId')
  const { month, year } = c.req.query()
  if (!month || !year) return c.json({ error: 'Month and year required' }, 400)

  const income = await prisma.income.findUnique({
    where: {
      userId_month_year: {
        userId,
        month: parseInt(month),
        year: parseInt(year)
      }
    }
  })
  return c.json(income || { salary: 0, atmBalance: 0 })
})

app.post('/api/income', authMiddleware, async (c) => {
  const userId = c.get('userId')
  const body = await c.req.json()
  
  const result = incomeSchema.safeParse(body)
  if (!result.success) {
    return c.json({ error: 'Invalid input', details: result.error.format() }, 400)
  }

  const { month, year, salary, atmBalance } = result.data

  const income = await prisma.income.upsert({
    where: {
      userId_month_year: {
        userId,
        month,
        year
      }
    },
    update: {
      salary,
      atmBalance
    },
    create: {
      userId,
      month,
      year,
      salary,
      atmBalance
    }
  })
  return c.json(income)
})

app.get('/api/income/total', authMiddleware, async (c) => {
const userId = c.get('userId')
  const agg = await prisma.income.aggregate({
    where: { userId },
    _sum: { salary: true }
  })
  return c.json({ totalSalary: agg._sum.salary ?? 0 })
})


// 2. Expense (Pengeluaran)
app.get('/api/expense', authMiddleware, async (c) => {
const userId = c.get('userId')
  const { month, year } = c.req.query()
  if (!month || !year) return c.json({ error: 'Month and year required' }, 400)

  const expenses = await prisma.expense.findMany({
    where: { userId, month: parseInt(month), year: parseInt(year) },
    orderBy: { createdAt: 'desc' }
  })
  return c.json(expenses)
})

app.post('/api/expense', authMiddleware, async (c) => {
  const userId = c.get('userId')
  const body = await c.req.json()

  const result = expenseSchema.safeParse(body)
  if (!result.success) {
    return c.json({ error: 'Invalid input', details: result.error.format() }, 400)
  }

  const { month, year, name, amount } = result.data

  const expense = await prisma.expense.create({
    data: {
      userId,
      month,
      year,
      name,
      amount
    }
  })
  return c.json(expense)
})

app.delete('/api/expense/:id', authMiddleware, async (c) => {
const userId = c.get('userId')
  const id = c.req.param('id')

  await prisma.expense.deleteMany({
    where: { id, userId }
  })
  return c.json({ success: true })
})

app.get('/api/expense/total', authMiddleware, async (c) => {
const userId = c.get('userId')
  const agg = await prisma.expense.aggregate({
    where: { userId },
    _sum: { amount: true }
  })
  return c.json({ totalExpense: agg._sum.amount ?? 0 })
})

// 2.1 Recent Expense (Detail pengeluaran terkini)
app.post('/api/recent-expense', authMiddleware, async (c) => {
  const userId = c.get('userId')
  const body = await c.req.json()

  const result = recentExpenseSchema.safeParse(body)
  if (!result.success) {
    return c.json({ error: 'Invalid input', details: result.error.format() }, 400)
  }

  const { name, amount, category, paymentMethod, date } = result.data
  const d = new Date(date)
  const month = d.getMonth() + 1
  const year = d.getFullYear()

  // Simpan ke RecentExpense (Tabel detail)
  const recentExpense = await prisma.recentExpense.create({
    data: {
      userId,
      name,
      amount,
      category,
      paymentMethod,
      month,
      year,
      createdAt: d
    }
  })

  // Simpan juga ke tabel Expense (hanya data relevan)
  await prisma.expense.create({
    data: {
      userId,
      name,
      amount,
      month,
      year,
      createdAt: d
    }
  })

  // Ambil user untuk mendapatkan googleSheetId & refreshToken
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { googleSheetId: true, refreshToken: true }
  })

  // Kirim ke Google Sheets
  // Format data: Tanggal, Nama, Jumlah, Kategori, Metode
  const day = String(d.getDate()).padStart(2, '0')
  const monthStr = String(d.getMonth() + 1).padStart(2, '0')
  const yearStr = d.getFullYear()
  const dateStr = `${day}/${monthStr}/${yearStr}`

  const sheetData = [
    dateStr,
    name,
    amount,
    category,
    paymentMethod
  ]
  await appendToSheet(user?.googleSheetId || null, user?.refreshToken || null, sheetData)

  return c.json(recentExpense)
})

// 3. Saving (Tabungan)
app.get('/api/saving', authMiddleware, async (c) => {
const userId = c.get('userId')
  const { month, year } = c.req.query()
  if (!month || !year) return c.json({ error: 'Month and year required' }, 400)

  const savings = await prisma.saving.findMany({
    where: { userId, month: parseInt(month), year: parseInt(year) },
    orderBy: { createdAt: 'desc' }
  })
  return c.json(savings)
})

app.post('/api/saving', authMiddleware, async (c) => {
  const userId = c.get('userId')
  const body = await c.req.json()

  const result = savingSchema.safeParse(body)
  if (!result.success) {
    return c.json({ error: 'Invalid input', details: result.error.format() }, 400)
  }

  const { month, year, instrument, amount } = result.data

  const saving = await prisma.saving.create({
    data: {
      userId,
      month,
      year,
      instrument,
      amount
    }
  })
  return c.json(saving)
})

app.delete('/api/saving/:id', authMiddleware, async (c) => {
const userId = c.get('userId')
  const id = c.req.param('id')

  await prisma.saving.deleteMany({
    where: { id, userId }
  })
  return c.json({ success: true })
})

app.get('/api/saving/total', authMiddleware, async (c) => {
const userId = c.get('userId')
  const agg = await prisma.saving.aggregate({
    where: { userId },
    _sum: { amount: true }
  })
  return c.json({ totalSaving: agg._sum.amount ?? 0 })
})

// 4. Other Fund (Dana Lainnya)
app.get('/api/other-fund', authMiddleware, async (c) => {
const userId = c.get('userId')
  const { month, year } = c.req.query()
  if (!month || !year) return c.json({ error: 'Month and year required' }, 400)

  const funds = await prisma.otherFund.findMany({
    where: { userId, month: parseInt(month), year: parseInt(year) },
    orderBy: { createdAt: 'desc' }
  })
  return c.json(funds)
})

app.post('/api/other-fund', authMiddleware, async (c) => {
  const userId = c.get('userId')
  const body = await c.req.json()

  const result = otherFundSchema.safeParse(body)
  if (!result.success) {
    return c.json({ error: 'Invalid input', details: result.error.format() }, 400)
  }

  const { month, year, name, amount } = result.data

  const fund = await prisma.otherFund.create({
    data: {
      userId,
      month,
      year,
      name,
      amount
    }
  })
  return c.json(fund)
})

app.delete('/api/other-fund/:id', authMiddleware, async (c) => {
const userId = c.get('userId')
  const id = c.req.param('id')

  await prisma.otherFund.deleteMany({
    where: { id, userId }
  })
  return c.json({ success: true })
})

app.get('/api/other-fund/total', authMiddleware, async (c) => {
const userId = c.get('userId')
  const agg = await prisma.otherFund.aggregate({
    where: { userId },
    _sum: { amount: true }
  })
  return c.json({ totalOtherFund: agg._sum.amount ?? 0 })
})

// 5. Evaluasi (All Totals)
app.get('/api/evaluation', authMiddleware, async (c) => {
const userId = c.get('userId')

  const [incomeAgg, expenseAgg, savingAgg, otherFundAgg] = await Promise.all([
    prisma.income.aggregate({ where: { userId }, _sum: { salary: true, atmBalance: true } }),
    prisma.expense.aggregate({ where: { userId }, _sum: { amount: true } }),
    prisma.saving.aggregate({ where: { userId }, _sum: { amount: true } }),
    prisma.otherFund.aggregate({ where: { userId }, _sum: { amount: true } })
  ])

  return c.json({
    totalSalary: (incomeAgg._sum.salary ?? 0) + (incomeAgg._sum.atmBalance ?? 0),
    totalExpense: expenseAgg._sum.amount ?? 0,
    totalSaving: savingAgg._sum.amount ?? 0,
    totalOtherFund: otherFundAgg._sum.amount ?? 0
  })
})

// 6. Chart Data Preparation
app.get('/api/evaluation/chart', authMiddleware, async (c) => {
  const userId = c.get('userId')

  // We fetch last 6 or 12 months, or just fetch all logic for the current year
  // Let's just group everything by month for the current year or provide a generic monthly aggregate
  
  // Since we want dynamic ranges, let's accept year as query:
  const { year } = c.req.query()
  if (!year) return c.json({ error: 'Year required' }, 400)

  const parsedYear = parseInt(year)

  // We will build an array of 12 month items for the chart
  const data = []
  
  for (let m = 1; m <= 12; m++) {
    const [income, expenseAgg, savingAgg, otherFundAgg] = await Promise.all([
      prisma.income.findUnique({ where: { userId_month_year: { userId, month: m, year: parsedYear } } }),
      prisma.expense.aggregate({ where: { userId, month: m, year: parsedYear }, _sum: { amount: true } }),
      prisma.saving.aggregate({ where: { userId, month: m, year: parsedYear }, _sum: { amount: true } }),
      prisma.otherFund.aggregate({ where: { userId, month: m, year: parsedYear }, _sum: { amount: true } })
    ])

    data.push({
      month: m,
      pendapatan: (income?.salary ?? 0) + (income?.atmBalance ?? 0),
      pengeluaran: expenseAgg._sum.amount ?? 0,
      tabungan: savingAgg._sum.amount ?? 0,
      danaLainnya: otherFundAgg._sum.amount ?? 0
    })
  }

  return c.json(data)
})

const port = parseInt(process.env.PORT || '3000')
console.log(`Server is running on port ${port}`)

serve({
  fetch: app.fetch,
  port
})

export default app
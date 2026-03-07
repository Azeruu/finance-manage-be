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

const google = new Google(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  `${BACKEND_URL}/api/auth/callback/google`
)

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use('*', secureHeaders())

app.use(
  '/*',
  cors({
    origin: (origin) => {
      // Izinkan localhost untuk dev, dan domain spesifik untuk prod
      const allowedOrigins = [
        FRONTEND_URL,
        'http://localhost:5173',
        'https://finance-manage-fe.vercel.app' // Gantilah dengan domain Vercel yang sesuai jika sudah tetap
      ]
      
      if (!origin) return FRONTEND_URL
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

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get('/', (c) => c.text('Finance API is running!'))

/**
 * Step 1: Redirect ke Google OAuth consent screen
 */
app.get('/api/auth/google', (c) => {
  const state = generateState()
  const codeVerifier = generateCodeVerifier()

  const url = google.createAuthorizationURL(state, codeVerifier, [
    'openid',
    'profile',
    'email',
  ])

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
    tokens = await google.validateAuthorizationCode(code, storedVerifier)
  } catch {
    return c.json({ error: 'Failed to exchange code for token' }, 400)
  }

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
  const user = await prisma.user.upsert({
    where: { googleId: googleUser.id },
    update: {
      email: googleUser.email,
      name: googleUser.name,
      avatar: googleUser.picture,
    },
    create: {
      email: googleUser.email,
      name: googleUser.name,
      avatar: googleUser.picture,
      googleId: googleUser.id,
    },
  })

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
    select: { id: true, name: true, email: true, avatar: true },
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
    prisma.income.aggregate({ where: { userId }, _sum: { salary: true } }),
    prisma.expense.aggregate({ where: { userId }, _sum: { amount: true } }),
    prisma.saving.aggregate({ where: { userId }, _sum: { amount: true } }),
    prisma.otherFund.aggregate({ where: { userId }, _sum: { amount: true } })
  ])

  return c.json({
    totalSalary: incomeAgg._sum.salary ?? 0,
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
      pendapatan: (income?.salary ?? 0),
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
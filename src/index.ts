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
app.use(
  '/*',
  cors({
    origin: FRONTEND_URL,
    allowHeaders: ['Content-Type', 'Authorization'],
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    credentials: true,
  })
)

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

/**
 * Step 2: Google redirect balik ke sini dengan code & state
 */
app.get('/api/auth/callback/google', async (c) => {
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

  // Set JWT di cookie
  setCookie(c, 'session', jwt, {
    httpOnly: true,
    maxAge: 60 * 60 * 24 * 7, // 7 hari
    path: '/',
    secure: true,
    sameSite: 'None',
  })

  // Hapus cookie sementara
  deleteCookie(c, 'oauth_state')
  deleteCookie(c, 'oauth_code_verifier')

  // Redirect ke frontend dashboard
  return c.redirect(`${FRONTEND_URL}/dashboard`)
})

/**
 * Middleware untuk mengecek User Authentication
 */
const authMiddleware = async (c: any, next: any) => {
  const token = getCookie(c, 'session')
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
  const token = getCookie(c, 'session')
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
  const { month, year, salary, atmBalance } = await c.req.json()

  const income = await prisma.income.upsert({
    where: {
      userId_month_year: {
        userId,
        month: parseInt(month),
        year: parseInt(year)
      }
    },
    update: {
      salary: parseFloat(salary),
      atmBalance: parseFloat(atmBalance)
    },
    create: {
      userId,
      month: parseInt(month),
      year: parseInt(year),
      salary: parseFloat(salary),
      atmBalance: parseFloat(atmBalance)
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
  const { month, year, name, amount } = await c.req.json()

  const expense = await prisma.expense.create({
    data: {
      userId,
      month: parseInt(month),
      year: parseInt(year),
      name,
      amount: parseFloat(amount)
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
  const { month, year, instrument, amount } = await c.req.json()

  const saving = await prisma.saving.create({
    data: {
      userId,
      month: parseInt(month),
      year: parseInt(year),
      instrument,
      amount: parseFloat(amount)
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

// 4. Evaluasi (All Totals)
app.get('/api/evaluation', authMiddleware, async (c) => {
const userId = c.get('userId')

  const [incomeAgg, expenseAgg, savingAgg] = await Promise.all([
    prisma.income.aggregate({ where: { userId }, _sum: { salary: true } }),
    prisma.expense.aggregate({ where: { userId }, _sum: { amount: true } }),
    prisma.saving.aggregate({ where: { userId }, _sum: { amount: true } })
  ])

  return c.json({
    totalSalary: incomeAgg._sum.salary ?? 0,
    totalExpense: expenseAgg._sum.amount ?? 0,
    totalSaving: savingAgg._sum.amount ?? 0
  })
})

const port = parseInt(process.env.PORT || '3000')
console.log(`Server is running on port ${port}`)

serve({
  fetch: app.fetch,
  port
})

export default app
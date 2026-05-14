require('dotenv').config()
const express = require('express')
const bcrypt  = require('bcryptjs')
const jwt     = require('jsonwebtoken')
const cors    = require('cors')
const { pool, setupDatabase } = require('./database')

const app    = express()
const PORT   = process.env.PORT || 3000
const SECRET = process.env.JWT_SECRET || 'easyroaster_secret'

app.use(cors())
app.use(express.json())

// ── Middleware: verify token ──────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'No token provided' })
  try {
    req.user = jwt.verify(token, SECRET)
    next()
  } catch {
    res.status(401).json({ error: 'Invalid token' })
  }
}

// ── Health check ──────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', server: 'EasyRoaster' })
})

// ════════════════════════════════════════════════════════════
// MASTER ADMIN ROUTES
// ════════════════════════════════════════════════════════════

// Login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username])
    const admin  = result.rows[0]
    if (!admin) return res.status(401).json({ error: 'Invalid credentials' })
    const valid  = await bcrypt.compare(password, admin.password)
    if (!valid)  return res.status(401).json({ error: 'Invalid credentials' })
    const token  = jwt.sign({ id: admin.id, role: 'admin' }, SECRET, { expiresIn: '30d' })
    res.json({ token, username: admin.username })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Get all businesses
app.get('/admin/businesses', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  try {
    const result = await pool.query(
      'SELECT id, name, owner, email, status, created_at FROM businesses ORDER BY created_at DESC'
    )
    res.json(result.rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Approve business
app.post('/admin/approve/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  try {
    await pool.query("UPDATE businesses SET status = 'active' WHERE id = $1", [req.params.id])
    res.json({ message: 'Business approved' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Deactivate business
app.post('/admin/deactivate/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  try {
    await pool.query("UPDATE businesses SET status = 'inactive' WHERE id = $1", [req.params.id])
    res.json({ message: 'Business deactivated' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Delete business
app.delete('/admin/business/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  try {
    await pool.query('DELETE FROM employees WHERE business_id = $1', [req.params.id])
    await pool.query('DELETE FROM relay_messages WHERE business_id = $1', [req.params.id])
    await pool.query('DELETE FROM businesses WHERE id = $1', [req.params.id])
    res.json({ message: 'Business deleted' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ════════════════════════════════════════════════════════════
// BUSINESS ROUTES
// ════════════════════════════════════════════════════════════

// Register
app.post('/business/register', async (req, res) => {
  const { name, owner, email, password } = req.body
  if (!name || !owner || !email || !password)
    return res.status(400).json({ error: 'All fields required' })
  try {
    const hash   = await bcrypt.hash(password, 10)
    const result = await pool.query(
      "INSERT INTO businesses (name, owner, email, password) VALUES ($1,$2,$3,$4) RETURNING id, name, status",
      [name, owner, email, hash]
    )
    res.json({ message: 'Registration submitted, awaiting approval', business: result.rows[0] })
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' })
    res.status(500).json({ error: err.message })
  }
})

// Login
app.post('/business/login', async (req, res) => {
  const { email, password } = req.body
  try {
    const result   = await pool.query('SELECT * FROM businesses WHERE email = $1', [email])
    const business = result.rows[0]
    if (!business) return res.status(401).json({ error: 'Invalid credentials' })
    const valid    = await bcrypt.compare(password, business.password)
    if (!valid)    return res.status(401).json({ error: 'Invalid credentials' })
    if (business.status === 'pending')
      return res.status(403).json({ error: 'Account pending approval' })
    if (business.status === 'inactive')
      return res.status(403).json({ error: 'Account deactivated' })
    const token = jwt.sign({ id: business.id, role: 'business' }, SECRET, { expiresIn: '30d' })
    res.json({ token, business: { id: business.id, name: business.name, owner: business.owner } })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Check status
app.get('/business/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'business') return res.status(403).json({ error: 'Forbidden' })
  try {
    const result = await pool.query('SELECT status FROM businesses WHERE id = $1', [req.user.id])
    res.json({ status: result.rows[0]?.status })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Register employee — returns unique code
app.post('/business/employee', authMiddleware, async (req, res) => {
  if (req.user.role !== 'business') return res.status(403).json({ error: 'Forbidden' })
  const { name } = req.body
  if (!name) return res.status(400).json({ error: 'Employee name required' })
  try {
    const code   = Math.random().toString(36).substring(2, 8).toUpperCase()
    const result = await pool.query(
      'INSERT INTO employees (name, code, business_id) VALUES ($1,$2,$3) RETURNING *',
      [name, code, req.user.id]
    )
    res.json({ employee: result.rows[0] })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Get all employees for a business
app.get('/business/employees', authMiddleware, async (req, res) => {
  if (req.user.role !== 'business') return res.status(403).json({ error: 'Forbidden' })
  try {
    const result = await pool.query(
      'SELECT id, name, code, created_at FROM employees WHERE business_id = $1',
      [req.user.id]
    )
    res.json(result.rows)
  } catch (err) {
    res.status(500)

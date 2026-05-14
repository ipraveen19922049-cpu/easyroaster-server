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

// Reactivate business
app.post('/admin/activate/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  try {
    await pool.query("UPDATE businesses SET status = 'active' WHERE id = $1", [req.params.id])
    res.json({ message: 'Business activated' })
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

// Register employee
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
    res.status(500).json({ error: err.message })
  }
})

// ════════════════════════════════════════════════════════════
// RELAY ROUTES
// ════════════════════════════════════════════════════════════

// Business pushes schedule to employee
app.post('/relay/push', authMiddleware, async (req, res) => {
  if (req.user.role !== 'business') return res.status(403).json({ error: 'Forbidden' })
  const { employee_code, message_type, payload } = req.body
  if (!employee_code || !message_type || !payload)
    return res.status(400).json({ error: 'employee_code, message_type and payload required' })
  try {
    await pool.query(
      'INSERT INTO relay_messages (employee_code, business_id, message_type, payload) VALUES ($1,$2,$3,$4)',
      [employee_code, req.user.id, message_type, JSON.stringify(payload)]
    )
    res.json({ message: 'Schedule pushed' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Employee pulls messages — deleted after delivery
app.get('/relay/pull', authMiddleware, async (req, res) => {
  if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' })
  try {
    const result = await pool.query(
      'SELECT * FROM relay_messages WHERE employee_code = $1 AND delivered = FALSE ORDER BY created_at ASC',
      [req.user.code]
    )
    if (result.rows.length > 0) {
      await pool.query(
        'UPDATE relay_messages SET delivered = TRUE WHERE employee_code = $1',
        [req.user.code]
      )
      await pool.query(
        'DELETE FROM relay_messages WHERE employee_code = $1 AND delivered = TRUE',
        [req.user.code]
      )
    }
    res.json(result.rows.map(r => ({ ...r, payload: JSON.parse(r.payload) })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ════════════════════════════════════════════════════════════
// EMPLOYEE ROUTES
// ════════════════════════════════════════════════════════════

// Login with code
app.post('/employee/login', async (req, res) => {
  const { code } = req.body
  if (!code) return res.status(400).json({ error: 'Code required' })
  try {
    const result = await pool.query(
      `SELECT e.*, b.name as business_name, b.status as business_status
       FROM employees e
       JOIN businesses b ON e.business_id = b.id
       WHERE e.code = $1`,
      [code.toUpperCase()]
    )
    const employee = result.rows[0]
    if (!employee) return res.status(404).json({ error: 'Invalid code' })
    if (employee.business_status !== 'active')
      return res.status(403).json({ error: 'Business account is not active' })
    const token = jwt.sign(
      { id: employee.id, role: 'employee', code: employee.code, business_id: employee.business_id },
      SECRET,
      { expiresIn: '30d' }
    )
    res.json({ token, employee: { name: employee.name, business: employee.business_name } })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ── Start server ──────────────────────────────────────────────
setupDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`EasyRoaster server running on port ${PORT}`)
  })
})

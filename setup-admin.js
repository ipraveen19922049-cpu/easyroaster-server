require('dotenv').config()
const bcrypt = require('bcryptjs')
const { pool, setupDatabase } = require('./database')

async function createAdmin() {
  await setupDatabase()
  
  const username = 'praveen'
  const password = 'changeme123'
  
  const hash = await bcrypt.hash(password, 10)
  
  try {
    await pool.query(
      'INSERT INTO admins (username, password) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING',
      [username, hash]
    )
    console.log('Admin created successfully')
    console.log('Username: praveen')
    console.log('Password: changeme123')
    console.log('IMPORTANT: Change your password after first login')
  } catch (err) {
    console.log('Error:', err.message)
  }
  
  process.exit()
}

createAdmin()

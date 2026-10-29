const express = require('express')
const db = require('../database/db')
const { isAuthenticated } = require('../middleware/auth')

const router = express.Router()

router.get('/', isAuthenticated, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId)
  user.theme = user.theme || 'light'
  res.render('profile', { user })
})

router.post('/', isAuthenticated, (req, res) => {
  // Validate display_name and theme inputs to prevent code injection attacks by:
  // 1. Implementing input sanitization to remove potentially dangerous characters (e.g., script tags)
  // 2. Adding length validation to prevent overly long inputs (e.g., maximum 100 characters)
  // 3. Using a whitelist of allowed characters (e.g., only allow alphanumeric, spaces, and common punctuation)
  // 4. Validating theme values to ensure they're within a predefined set (e.g., 'light', 'dark', 'auto')
  // 5. Implementing input validation to prevent injection of malicious scripts or commands
  const { display_name, theme } = req.body // No input validation on display_name and theme. Vulnerable to code injection attacks.
  db.prepare(
    'UPDATE users SET display_name = ?, theme = ? WHERE id = ?'
  ).run(display_name || null, theme || 'light', req.session.userId)
  req.session.display_name = display_name || null
  req.session.theme = theme || 'light'
  res.redirect('/profile')
})

module.exports = router

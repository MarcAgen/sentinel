const express = require('express')
const db = require('../database/db')

const router = express.Router()

router.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/dashboard')
  res.render('login', { error: req.query.error === '1' })
})

router.post('/login', (req, res) => {
  // Validate email and password inputs to prevent SQL Injection attacks by:
  // 1. Using parameterized queries (already implemented with ? placeholders)
  // 2. Implementing input sanitization to remove potentially dangerous characters
  // 3. Adding length validation to prevent overly long inputs
  // 4. Validating email format using a regular expression (e.g., /^[^\s@]+@[^\s@]+\.[^\s@]+$/)
  // 5. Implementing rate limiting to prevent brute force attacks
  const { email, password } = req.body // No input validation on email and password. Vulnerable to SQL Injection attacks.
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  if (!user || user.password !== password) {
    // NOTE: failed login redirects to /login?error=1 (HTTP 302, not 401)
    // A generic logging middleware that only reads res.statusCode will NOT
    // distinguish a failed login from a successful one -- both return 302.
    // To emit an auth_failure event, either instrument this block explicitly
    // or check res.getHeader('Location') in your middleware via res.on('finish').
		// **VULNERABILITY**: No rate limiting on login attempts.
		// **Exploit**: Brute-force attacks could be used to guess passwords.
		// **Fix**: Implement rate limiting (e.g., using `express-rate-limit`).
		// **Wazuh Monitoring**: Use Wazuh's `authentication_failure` rules to detect repeated failed login attempts.
    return res.redirect('/login?error=1')
  }
	// **VULNERABILITY**: Plain-text password comparison.
	// **Exploit**: Passwords are stored in plain text, which is insecure.
	// **Fix**: Use bcrypt or another secure hashing algorithm for passwords.
	// **Wazuh Monitoring**: Use Wazuh's `authentication_failure` and `password_policy` rules to monitor for insecure password handling.
  req.session.userId = user.id
  req.session.role = user.role
  req.session.username = user.username
  req.session.display_name = user.display_name || null
  req.session.theme = user.theme || 'light'
  res.redirect('/dashboard')
})

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'))
})

module.exports = router

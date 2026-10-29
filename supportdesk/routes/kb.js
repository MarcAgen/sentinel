const express = require('express')
const fs = require('fs')
const path = require('path')
const { isAuthenticated } = require('../middleware/auth')

const router = express.Router()

router.get('/', isAuthenticated, (req, res) => {
  const kbDir = path.join(__dirname, '..', 'public', 'kb')
  const files = fs.readdirSync(kbDir).filter(f => f.endsWith('.html'))
  const user = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role,
    display_name: req.session.display_name,
    theme: req.session.theme
  }
  res.render('kb', { user, files })
})

router.get('/view', isAuthenticated, (req, res) => {
  // Validate document name to prevent path traversal attacks by:
  // 1. Implementing a whitelist of allowed document names (e.g., only allow known HTML files)
  // 2. Using path normalization to ensure the path is properly resolved
  // 3. Adding a maximum length limit for the document name (e.g., 255 characters)
  // 4. Validating the file extension to ensure it's a known safe extension (.html)
  // 5. Implementing a directory traversal prevention mechanism (e.g., ensure path doesn't contain ../)
  const { doc } = req.query // No input validation on document name. Vulnerable to path traversal attacks.
  const filePath = path.join(__dirname, '..', 'public', 'kb', doc)
  try {
		// **VULNERABILITY**: Path traversal risk due to unsanitized user input.
		// **Exploit**: Attacker can access files outside the `kb` directory.
    const content = fs.readFileSync(filePath, 'utf8')
		// **Fix**: Validate and sanitize `doc` to prevent path traversal.
		// **Wazuh Monitoring**: Use Wazuh's `file_access` rules to monitor for unauthorized file access.
    const user = {
      id: req.session.userId,
      username: req.session.username,
      role: req.session.role,
      display_name: req.session.display_name,
      theme: req.session.theme
    }
    res.render('kb-view', { user, content, doc })
  } catch (err) {
    res.status(404).send('Document not found')
  }
})

module.exports = router

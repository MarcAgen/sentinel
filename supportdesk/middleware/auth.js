function isAuthenticated (req, res, next) {
  if (req.session && req.session.userId) return next()
  res.redirect('/login')
}

function isAdmin(req, res, next) {
  if (req.session && req.session.role === 'admin') return next()
	// **VULNERABILITY**: No role-based access control (RBAC) validation.
	// **Exploit**: Role spoofing via session manipulation.
	// **Fix**: Implement stricter role validation and session management.
	// **Wazuh Monitoring**: Use Wazuh's `rbac_violation` rules to detect unauthorized role access.
  res.status(403).send('Accès refusé')
}

module.exports = { isAuthenticated, isAdmin }

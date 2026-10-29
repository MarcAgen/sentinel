const express = require('express')
const session = require('express-session')
const path = require('path')

const db = require('./database/db')
const seed = require('./database/seed')
const { isAuthenticated } = require('./middleware/auth')

const authRouter = require('./routes/auth')
const ticketsRouter = require('./routes/tickets')
const adminRouter = require('./routes/admin')
const profileRouter = require('./routes/profile')
const kbRouter = require('./routes/kb')

const app = express()
const PORT = process.env.PORT || 3000 // Using environment variable for port without validation. Ensure PORT is secure and not exposed to users.

// Read real client IP from X-Forwarded-For when behind a proxy/Docker bridge
app.set('trust proxy', true)
// **VULNERABILITY**: Trusting all X-Forwarded-For headers can expose internal IPs.
// **Exploit**: Attacker can spoof X-Forwarded-For to reveal internal network topology.
// **Fix**: Validate and limit trusted proxies.
// **Wazuh Monitoring**: Use Wazuh's `file_integrity` and `auditd` rules to monitor changes to proxy settings and detect unauthorized modifications.

// NOTE: No CSRF protection for sensitive routes (e.g., login, logout, session management).
// **VULNERABILITY**: Lack of CSRF tokens on sensitive routes.
// **Exploit**: Cross-Site Request Forgery (CSRF) attacks could hijack authenticated sessions.
// **Fix**: Add CSRF protection using middleware like `csurf`.
// **Wazuh Monitoring**: Monitor for unusual session changes using Wazuh's `session_management` rules.

seed()

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

app.use(express.urlencoded({ extended: false }))
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret', // Using environment variable for session secret without validation. Ensure SESSION_SECRET is secure and not exposed to users.
  resave: false,
  saveUninitialized: false
}))
app.use(require('./middleware/logger'))
// NOTE: Session secret is hardcoded to 'dev-secret' in development.
// **VULNERABILITY**: Weak session secret.
// **Exploit**: Session fixation or hijacking.
// **Fix**: Use a strong, environment-specific secret.
// **Wazuh Monitoring**: Use Wazuh's `session_management` and `authentication_failure` rules to detect session-related anomalies.

app.get('/', (req, res) => res.redirect('/login'))

app.use('/', authRouter)
app.use('/tickets', ticketsRouter)
app.use('/admin', adminRouter)
app.use('/profile', profileRouter)
app.use('/kb', kbRouter)

app.get('/dashboard', isAuthenticated, (req, res) => {
  const user = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role,
    display_name: req.session.display_name,
    theme: req.session.theme
  }
  const total = db.prepare('SELECT COUNT(*) as n FROM tickets').get().n
  const open = db.prepare("SELECT COUNT(*) as n FROM tickets WHERE status = 'open'").get().n
  const inProgress = db.prepare("SELECT COUNT(*) as n FROM tickets WHERE status = 'in_progress'").get().n
  const urgent = db.prepare("SELECT COUNT(*) as n FROM tickets WHERE priority = 'urgent'").get().n
  const recent = db.prepare(`
    SELECT t.*, u.username as creator_name
    FROM tickets t LEFT JOIN users u ON t.created_by = u.id
    ORDER BY t.created_at DESC LIMIT 5
  `).all()
  res.render('dashboard', { user, stats: { total, open, inProgress, urgent }, recent })
})

// Global error handler -- instrument this to capture 500 events
app.use((err, req, res, next) => {
  res.status(500).send('Internal server error') // Error message reveals internal server details which can be used by attackers.
})
// **VULNERABILITY**: No detailed error logging or sanitization.
// **Exploit**: Stack traces or sensitive data leakage.
// **Fix**: Log errors without exposing sensitive data and sanitize responses.
// **Wazuh Monitoring**: Use Wazuh's `error_logging` rules to monitor server errors and detect unusual patterns.

app.listen(PORT, () => {
  console.log(`SupportDesk running on http://localhost:${PORT}`)
})

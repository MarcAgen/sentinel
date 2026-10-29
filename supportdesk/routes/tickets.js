const express = require('express')
const db = require('../database/db')
const { isAuthenticated } = require('../middleware/auth')

const router = express.Router()

router.get('/', isAuthenticated, (req, res) => {
  const { view, status, priority, sort, dir } = req.query
  const viewMine = view === 'mine'

  // Validate query parameters to prevent SQL injection attacks by:
  // 1. Implementing input sanitization for all query parameters
  // 2. Using parameterized queries for all database operations
  // 3. Adding length validation to prevent overly long inputs
  // 4. Validating status and priority values against a predefined whitelist
  // 5. Implementing proper error handling for invalid inputs
  let where = viewMine ? `WHERE t.created_by = ${req.session.userId}` : 'WHERE 1=1'
  if (status) where += ` AND t.status = '${status}'`
  if (priority) where += ` AND t.priority = '${priority}'`

  const sortCol = sort || 'created_at'
  const sortDir = dir === 'asc' ? 'ASC' : 'DESC'
  const orderBy = `ORDER BY ${sortCol} ${sortDir}`

  const tickets = db.prepare(
    `SELECT t.*, u.username as creator_name, u.display_name as creator_display_name
     FROM tickets t LEFT JOIN users u ON t.created_by = u.id ${where} ${orderBy}`
  ).all()

  const user = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role,
    display_name: req.session.display_name,
    theme: req.session.theme
  }
  res.render('tickets', {
    tickets,
    user,
    search: '',
    viewMine,
    filters: { status: status || '', priority: priority || '', sort: sortCol, dir: sortDir }
  })
})

router.post('/search', isAuthenticated, (req, res) => {
  const { search } = req.body // No input validation on search query. Vulnerable to SQL Injection attacks.
  const results = db.prepare(
    `SELECT t.*, u.username as creator_name, u.display_name as creator_display_name
     FROM tickets t LEFT JOIN users u ON t.created_by = u.id
     WHERE t.title LIKE '%${search}%' OR t.description LIKE '%${search}%'`
  ).all()
  const user = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role,
    display_name: req.session.display_name,
    theme: req.session.theme
  }
  res.render('tickets', { tickets: results, user, search, viewMine: false, filters: {} })
})

// NOTE: no ownership check -- any authenticated user can export any ticket (IDOR)
// Detection requires logging both the requester identity and the ticket owner
// in the same event; a generic HTTP status-based rule will never see this (200 OK).
// **VULNERABILITY**: Insecure Direct Object Reference (IDOR) in ticket export.
// **Exploit**: Users can access or export tickets they don't own.
// **Fix**: Add ownership checks to ensure users can only access their own tickets.
// **Wazuh Monitoring**: Use Wazuh's `access_control` rules to detect unauthorized access to sensitive data.
router.get('/:id/export', isAuthenticated, (req, res) => {
  // Add ownership check to prevent IDOR by:
  // 1. Validating that the ticket belongs to the current user or is assigned to them
  // 2. Implementing proper authorization checks before allowing export
  // 3. Logging the request with both user identity and ticket ownership information
  // 4. Implementing rate limiting to prevent abuse of the export functionality
  // 5. Adding proper error handling for invalid ticket IDs
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(req.params.id)
  if (!ticket) return res.status(404).send('Not found')
	// **VULNERABILITY**: SQL injection risk due to lack of parameter sanitization.
	// **Exploit**: Attacker can manipulate `req.params.id` to execute arbitrary SQL.
	// **Fix**: Use parameterized queries (already done here, but ensure all queries follow this pattern).
	// **Wazuh Monitoring**: Use Wazuh's `sql_injection` rules to detect unusual SQL patterns.
  const comments = db.prepare(
    'SELECT * FROM comments WHERE ticket_id = ? ORDER BY created_at ASC'
  ).all(req.params.id)
  let output = `TICKET #${ticket.id}\n`
  output += `Title: ${ticket.title}\n`
  output += `Status: ${ticket.status} | Priority: ${ticket.priority}\n`
  output += `Description: ${ticket.description || 'N/A'}\n\n`
  output += `COMMENTS (${comments.length})\n`
  output += '-'.repeat(40) + '\n'
  for (const c of comments) {
    output += `[${c.created_at}] ${c.content}\n`
  }
  res.setHeader('Content-Type', 'text/plain')
  res.setHeader('Content-Disposition', `attachment; filename="ticket-${ticket.id}.txt"`)
  res.send(output)
})

router.get('/:id', isAuthenticated, (req, res) => {
  const ticket = db.prepare(`
    SELECT t.*, u.username as creator_name, a.username as assignee_name
    FROM tickets t
    LEFT JOIN users u ON t.created_by = u.id
    LEFT JOIN users a ON t.assigned_to = a.id
    WHERE t.id = ?
  `).get(req.params.id)
  if (!ticket) return res.status(404).send('Ticket not found')
  const comments = db.prepare(`
    SELECT c.*, u.username as author_name
    FROM comments c
    LEFT JOIN users u ON c.author_id = u.id
    WHERE c.ticket_id = ?
    ORDER BY c.created_at ASC
  `).all(req.params.id)
  const user = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role,
    display_name: req.session.display_name,
    theme: req.session.theme
  }
  res.render('ticket-detail', { ticket, comments, user })
})

router.post('/:id/comment', isAuthenticated, (req, res) => {
  const { content } = req.body
	// **Exploit**: CSRF attacks could allow unauthorized users to post malicious comments.
	// **Fix**: Add CSRF tokens to forms.
	// **Wazuh Monitoring**: Use Wazuh's `csrf_protection` rules to detect CSRF-related anomalies.
  const now = new Date().toISOString()
  db.prepare(
    'INSERT INTO comments (ticket_id, author_id, content, created_at) VALUES (?, ?, ?, ?)'
  ).run(req.params.id, req.session.userId, content, now)
  res.redirect('/tickets/' + req.params.id)
})

module.exports = router

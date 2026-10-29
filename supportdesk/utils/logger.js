/**
 * @module logger
 * @description Provides a structured logging utility that outputs JSON lines to stdout,
 * compatible with Wazuh ingestion, adhering to the schema defined in CONTRACT.md.
 */
const log = (level, event, message, context = {}) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level: level,
    event: event,
    message: message,
    // Include context fields from CONTRACT.md if available
    source_ip: context.source_ip || null,
    user: context.user || null,
    http_code: context.http_code || null,
    headers: context.headers || null,
    method: context.method || null,
    route: context.route || null,
    query: context.query || null,
    body: context.body || null,
    duration_ms: context.duration_ms || null, // Added duration_ms from CONTRACT.md
  };
  // Log as a single JSON line to stdout for easy collection by Wazuh agent
  console.log(JSON.stringify(logEntry))
}

module.exports = {
  /**
   * Logs an informational event.
   * @param {string} message - A human-readable message describing the event.
   * @param {string} event - A structured event identifier (e.g., 'REQUEST_START').
   * @param {object} context - Contextual data adhering to CONTRACT.md schema.
   */
  info: (message, event, context) => log('INFO', event, message, context),
  /**
   * Logs a warning event.
   * @param {string} message - A human-readable message describing the event.
   * @param {string} event - A structured event identifier (e.g., 'ADMIN_LOGIN').
   * @param {object} context - Contextual data adhering to CONTRACT.md schema.
   */
  warn: (message, event, context) => log('WARN', event, message, context),
  /**
   * Logs an error event.
   * @param {string} message - A human-readable message describing the error.
   * @param {string} event - A structured event identifier (e.g., 'INVALID_PASSWORD').
   * @param {object} context - Contextual data adhering to CONTRACT.md schema.
   */
  error: (message, event, context) => log('ERROR', event, message, context),
}
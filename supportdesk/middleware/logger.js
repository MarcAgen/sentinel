// Logging middleware skeleton -- implement to make SupportDesk observable.
//
// Mount in app.js AFTER the session middleware and BEFORE the routers:
//   app.use(require('./middleware/logger'))
//
// Emit structured events following the schema agreed in your CONTRACT.md.
// Which fields to capture, from which part of each request, and how to detect
// failed authentication are yours to determine.
const logger = require('../utils/logger');

// Generic logger for every route that has this Middleware active.
// The logs produced by this Middleware should only ever be used for debugging, as the logs provided here are GENERIC!
// It thus doesn't do much against vulnerabilities against specific routes.
function logger(req, res, next) {
  const startTime = Date.now();
  
  const context = {
    source_ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
    method: req.method,
    route: req.originalUrl,
    query: req.query ? JSON.stringify(req.query) : null,
    headers: JSON.stringify(req.headers),
    // Assuming session is available before logger in app.js
    user: req.session?.userId ? `user_${req.session.userId}` : null,
  };

  // Log request start
  logger.info('Request received', 'REQUEST_START', 'Incoming HTTP request', context);

  // Capture response details when the response is finished
  res.on('finish', () => {
    const duration_ms = Date.now() - startTime;
    const httpCode = res.statusCode;
    context.http_code = httpCode;
    context.duration_ms = duration_ms; // Add duration to context
    logger.info('Request finished', 'REQUEST_END', `HTTP response sent with status ${httpCode}`, context);
  });

  // Handle potential errors during request processing
  req.on('error', (err) => {
    const duration_ms = Date.now() - startTime;
    context.duration_ms = duration_ms; // Add duration to context on error
    logger.error('Request error', 'REQUEST_ERROR', err.message, { ...context, error_details: err.stack });
    next(err);
  });

  next();
}

module.exports = logger
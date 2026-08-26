// Consistent error response format across every route
// Every error: { error: string, code?: string, details?: string[] }

function sendError(res, status, message, code = null, details = null) {
  const body = { error: message };
  if (code)    body.code    = code;
  if (details) body.details = details;
  return res.status(status).json(body);
}

const E = {
  badRequest:    (res, msg, details) => sendError(res, 400, msg, 'BAD_REQUEST',    details),
  unauthorized:  (res, msg)          => sendError(res, 401, msg, 'UNAUTHORIZED'),
  forbidden:     (res, msg)          => sendError(res, 403, msg, 'FORBIDDEN'),
  notFound:      (res, msg)          => sendError(res, 404, msg, 'NOT_FOUND'),
  conflict:      (res, msg)          => sendError(res, 409, msg, 'CONFLICT'),
  locked:        (res, msg)          => sendError(res, 423, msg, 'ACCOUNT_LOCKED'),
  tooMany:       (res, msg)          => sendError(res, 429, msg, 'RATE_LIMITED'),
  server:        (res, msg)          => sendError(res, 500, msg || 'Internal server error', 'INTERNAL_ERROR'),
};

// Pagination helper — returns a consistent wrapper object
function paginate(query, countQuery, page, limit, ...args) {
  const offset     = (page - 1) * limit;
  const total      = countQuery.get(...args).n;
  const data       = query.all(...args, limit, offset);
  const totalPages = Math.ceil(total / limit);
  return {
    data,
    pagination: {
      page, limit, total, totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1,
    },
  };
}

module.exports = { sendError, E, paginate };

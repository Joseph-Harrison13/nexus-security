// Express middleware factory — validates req.body against a Zod schema.
// On failure: returns 400 with { error, details: [list of field errors] }
// On success: replaces req.body with the parsed (coerced + trimmed) value
function validate(schema) {
  return (req, res, next) => {
    try {
      const result = schema.safeParse(req.body ?? {});
      if (!result.success) {
        const details = result.error.issues.map(e => {
          const field = e.path.length ? e.path.join('.') : 'body';
          return `${field}: ${e.message}`;
        });
        return res.status(400).json({ error: 'Validation failed', code: 'VALIDATION_ERROR', details });
      }
      req.body = result.data;
      next();
    } catch (err) {
      console.error('[validate] Schema error:', err.message);
      res.status(400).json({ error: 'Invalid request body', code: 'VALIDATION_ERROR' });
    }
  };
}

module.exports = validate;

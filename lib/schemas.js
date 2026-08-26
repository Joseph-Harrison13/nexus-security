const { z } = require('zod');

// Reusable field types
const email = z.string()
  .email('Invalid email address')
  .transform(v => v.toLowerCase().trim());
const name  = z.string().min(1, 'Name is required').max(100)
  .transform(v => v.trim());

// Password must be 8+ chars with uppercase, lowercase, number, and special char
const strongPassword = z.string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password is too long')
  .refine(p => /[A-Z]/.test(p), { message: 'Password must contain at least one uppercase letter' })
  .refine(p => /[a-z]/.test(p), { message: 'Password must contain at least one lowercase letter' })
  .refine(p => /[0-9]/.test(p), { message: 'Password must contain at least one number' })
  .refine(p => /[^A-Za-z0-9]/.test(p), { message: 'Password must contain at least one special character (!@#$%...)' });

const schemas = {
  register: z.object({
    firstName:    z.string().min(1, 'First name is required').max(100).transform(v => v.trim()),
    lastName:     z.string().min(1, 'Last name is required').max(100).transform(v => v.trim()),
    businessName: z.string().min(1, 'Business name is required').max(200).transform(v => v.trim()),
    email:        email,
    password:     strongPassword,
    plan:         z.enum(['Starter', 'Growth', 'Pro']).optional(),
  }),

  login: z.object({
    email:    email,
    password: z.string().min(1, 'Password is required'),
  }),

  verify2fa: z.object({
    tempToken: z.string().min(1),
    code:      z.string().min(6).max(12),
  }),

  verifyLocation: z.object({
    tempToken: z.string().min(1),
    code:      z.string().min(6).max(6),
  }),

  forgotPassword: z.object({
    email: email,
  }),

  resetPassword: z.object({
    token:    z.string().min(1),
    password: strongPassword,
  }),

  createUser: z.object({
    email:    email,
    password: strongPassword,
    name:     name,
    role:     z.enum(['Admin', 'User']).default('User'),
    plan:     z.enum(['Starter', 'Growth', 'Pro']).default('Starter'),
  }),

  updateUser: z.object({
    name:     name.optional(),
    password: strongPassword.optional(),
    role:     z.enum(['Admin', 'User']).optional(),
    plan:     z.enum(['Starter', 'Growth', 'Pro']).optional(),
  }).refine(d => Object.keys(d).length > 0, { message: 'Nothing to update' }),

  contact: z.object({
    firstName:    z.string().max(100).trim().optional(),
    lastName:     z.string().max(100).trim().optional(),
    email:        email,
    businessName: z.string().max(200).trim().optional(),
    interestedIn: z.string().max(100).trim().optional(),
    message:      z.string().min(1, 'Message is required').max(2000).trim(),
  }),

  confirmTotp: z.object({
    code: z.string().length(6, 'Code must be 6 digits'),
  }),

  disableTotp: z.object({
    password: z.string().min(1, 'Password is required'),
  }),
};

module.exports = { schemas, strongPassword };

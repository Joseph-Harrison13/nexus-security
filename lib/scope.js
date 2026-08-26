// Tenant-scoping helpers. The invariant: a caller may only ever see or touch
// rows in their own organization — except a SuperAdmin, who spans all orgs.
//
//   • SuperAdmin  → everything, every org
//   • Admin       → their own organization (org_id === req.user.org_id)
//   • User        → only their own rows (user_id === req.user.sub)

// Can the caller access a specific fetched row? The row must carry user_id and
// (for the Admin case) org_id.
function canAccessRow(req, row) {
  if (!row) return false;
  if (req.user.role === 'SuperAdmin') return true;
  if (row.user_id === req.user.sub) return true;
  if (req.user.role === 'Admin' && row.org_id != null && row.org_id === req.user.org_id) return true;
  return false;
}

// Build a WHERE fragment + params that scope a listing to what the caller may see.
// `col` prefixes (e.g. 'f') let callers target a specific table alias.
function listScope(req, { userCol = 'user_id', orgCol = 'org_id' } = {}) {
  if (req.user.role === 'SuperAdmin') return { sql: '1=1', params: [] };
  if (req.user.role === 'Admin')      return { sql: `${orgCol} = ?`,  params: [req.user.org_id] };
  return { sql: `${userCol} = ?`, params: [req.user.sub] };
}

// Can the caller manage this target USER row (the users table keys on `id`)?
// SuperAdmin manages anyone; an Org Admin only their own organization's members.
function canManageUser(req, target) {
  if (!target) return false;
  if (req.user.role === 'SuperAdmin') return true;
  // Only an Org Admin may manage other members of their organization. A regular
  // User must never manage a peer — without this role check, any same-org user
  // could overwrite a colleague's password (account takeover). Matches canAccessRow.
  if (req.user.role === 'Admin' && target.org_id != null && target.org_id === req.user.org_id) return true;
  return false;
}

// Listing scope for the users table itself ("own" row = id === sub).
function usersScope(req) {
  if (req.user.role === 'SuperAdmin') return { sql: '1=1', params: [] };
  if (req.user.role === 'Admin')      return { sql: 'org_id = ?', params: [req.user.org_id] };
  return { sql: 'id = ?', params: [req.user.sub] };
}

module.exports = { canAccessRow, listScope, canManageUser, usersScope };

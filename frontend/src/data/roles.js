export const ROLES = {
  ADMIN: "admin",
  ANALYST: "analyst",
  DEVICE: "device",
};

export const ROLE_LABELS = {
  [ROLES.ADMIN]: "Administrator",
  [ROLES.ANALYST]: "Security Analyst",
  [ROLES.DEVICE]: "Protected Device",
};

export function normalizeRole(role) {
  if (!role) return "";
  return String(role).toLowerCase();
}

export function isAdmin(user) {
  const r = normalizeRole(user?.role);
  return r === ROLES.ADMIN;
}

export function isDevice(user) {
  const r = normalizeRole(user?.role);
  return r === ROLES.DEVICE;
}

export function isAnalyst(user) {
  const r = normalizeRole(user?.role);
  return r === ROLES.ANALYST || r === ROLES.ADMIN;
}

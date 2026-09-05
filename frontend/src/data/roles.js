export const ROLES = {
  ADMIN: "admin",
  ANALYST: "analyst",
};

export const ROLE_LABELS = {
  [ROLES.ADMIN]: "Administrator",
  [ROLES.ANALYST]: "Security Analyst",
};

export function isAdmin(user) {
  return user?.role === ROLES.ADMIN;
}

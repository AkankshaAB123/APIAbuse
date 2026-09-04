import { useState } from "react";
import { LogOut, UserCircle } from "lucide-react";
import { ROLE_LABELS } from "../data/roles";

function ProfileMenu({ user, onLogout }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="profile-menu">
      <button
        className="profile-trigger"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
      >
        <UserCircle size={22} />
        <span>
          {user?.username || user?.name || "admin"}
          <em>{ROLE_LABELS[user?.role] || "Security Analyst"}</em>
          <small>Online</small>
        </span>
      </button>

      {open && (
        <div className="profile-dropdown">
          <button type="button">
            <UserCircle size={16} />
            {ROLE_LABELS[user?.role] || "Security Analyst"}
          </button>
          <button type="button" onClick={onLogout}>
            <LogOut size={16} />
            Logout
          </button>
        </div>
      )}
    </div>
  );
}

export default ProfileMenu;

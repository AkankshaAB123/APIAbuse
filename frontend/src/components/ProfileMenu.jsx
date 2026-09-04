import { useState } from "react";
import { LogOut, Settings, UserCircle } from "lucide-react";

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
          {user?.name || "Admin"}
          <small>Online</small>
        </span>
      </button>

      {open && (
        <div className="profile-dropdown">
          <button type="button">
            <UserCircle size={16} />
            Profile
          </button>
          <button type="button">
            <Settings size={16} />
            Security Settings
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

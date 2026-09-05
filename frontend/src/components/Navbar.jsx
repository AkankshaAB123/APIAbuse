import ProfileMenu from "./ProfileMenu";

function Navbar({ user, onLogout }) {
  return (
    <header className="navbar">
      <div className="navbar-title">
        ThreatGuard
        <span>AI-Powered API Security</span>
      </div>

      <div className="navbar-user">
        <ProfileMenu
          user={user}
          onLogout={onLogout}
        />
      </div>
    </header>
  );
}

export default Navbar;

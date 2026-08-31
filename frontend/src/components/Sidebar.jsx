function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <h2>ThreatGuard</h2>
      </div>

      <nav className="sidebar-menu">
        <a href="/">Dashboard</a>
        <a href="/threats">Threats</a>
        <a href="/analytics">Analytics</a>
      </nav>
    </aside>
  );
}

export default Sidebar;

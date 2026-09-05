import { Link } from "react-router-dom";

function Sidebar() {
  return (
    <aside className="sidebar">

      <div className="sidebar-logo">
        <h2>ThreatGuard</h2>
      </div>

      <nav className="sidebar-menu">

        {/* ADMIN */}

        <div className="sidebar-section-title">
          ADMIN
        </div>

        <Link to="/">
          Dashboard
        </Link>

        <Link to="/threats">
          Threats
        </Link>

        <Link to="/analytics">
          Analytics
        </Link>


        {/* ENTERPRISE */}

        <div className="sidebar-section-title">
          ENTERPRISE
        </div>

        <Link to="/enterprise">
          API Security
        </Link>


        {/* SIMULATION */}

        <div className="sidebar-section-title">
          SIMULATION
        </div>

        <Link to="/attack-simulation">
          Attack Simulation
        </Link>

      </nav>

    </aside>
  );
}

export default Sidebar;

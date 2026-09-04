import { NavLink } from "react-router-dom";

const navSections = [
  {
    title: "OVERVIEW",
    links: [
      { to: "/", label: "Dashboard" },
    ],
  },
  {
    title: "THREAT MANAGEMENT",
    links: [
      { to: "/threats", label: "Threats" },
      { to: "/alerts", label: "Alerts" },
      { to: "/analytics", label: "Analytics" },
    ],
  },
  {
    title: "SECURITY TESTING",
    links: [
      { to: "/attack-simulation", label: "Attack Simulation" },
      { to: "/security-test", label: "New Security Test" },
    ],
  },
  {
    title: "AI SECURITY",
    links: [
      { to: "/ai-copilot", label: "AI Copilot" },
    ],
  },
  {
    title: "ENTERPRISE",
    links: [
      { to: "/enterprise", label: "API Security" },
      { to: "/api-inventory", label: "API Inventory" },
    ],
  },
];

function Sidebar() {
  return (
    <aside className="sidebar">

      <div className="sidebar-logo">
        <h2>ThreatGuard</h2>
        <span>Monitor. Detect. Explain.</span>
      </div>

      <nav className="sidebar-menu">
        {navSections.map((section) => (
          <div key={section.title} className="sidebar-section">
            <div className="sidebar-section-title">
              {section.title}
            </div>

            {section.links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) =>
                  isActive ? "active" : undefined
                }
              >
                {link.label}
              </NavLink>
            ))}
          </div>
        ))}

      </nav>

    </aside>
  );
}

export default Sidebar;

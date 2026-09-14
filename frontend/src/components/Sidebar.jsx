import { NavLink } from "react-router-dom";
import { isAdmin } from "../data/roles";
import {
  LayoutDashboard,
  ShieldAlert,
  BellRing,
  Activity,
  BarChart3,
  TerminalSquare,
  Swords,
  FlaskConical,
  Bot,
  Building2,
  Database
} from "lucide-react";

const navSections = [
  {
    title: "OVERVIEW",
    links: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard },
    ],
  },
  {
    title: "THREAT MANAGEMENT",
    links: [
      { to: "/threats", label: "Threats", icon: ShieldAlert },
      { to: "/alerts", label: "Alerts", icon: BellRing },
      { to: "/soc-live", label: "Live SOC", icon: Activity },
      { to: "/analytics", label: "Analytics", icon: BarChart3 },
    ],
  },
  {
    title: "SECURITY TESTING",
    links: [
      { to: "/attacker-console", label: "Attacker Console", icon: TerminalSquare },
      { to: "/attack-simulation", label: "Attack Simulation", icon: Swords },
      { to: "/security-test", label: "New Security Test", icon: FlaskConical },
    ],
  },
  {
    title: "AI SECURITY",
    links: [
      { to: "/ai-copilot", label: "AI Copilot", icon: Bot },
    ],
  },
  {
    title: "ENTERPRISE",
    links: [
      { to: "/enterprise", label: "API Security", icon: Building2 },
      { to: "/api-inventory", label: "API Inventory", icon: Database },
    ],
  },
];

function Sidebar({ user }) {
  const visibleSections = navSections
    .map((section) => ({
      ...section,
      links: section.links.filter((link) => {
        const adminOnly = [
          "/attacker-console",
          "/attack-simulation",
          "/security-test",
          "/enterprise",
        ].includes(link.to);

        return !adminOnly || isAdmin(user);
      }),
    }))
    .filter((section) => section.links.length > 0);

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-brand-mark">
          <ShieldAlert size={28} className="brand-icon" />
          <h2>ThreatGuard</h2>
        </div>
        <span className="sidebar-kicker">Monitor. Detect. Explain.</span>
      </div>

      <nav className="sidebar-menu">
        {visibleSections.map((section) => (
          <div key={section.title} className="sidebar-section">
            <div className="sidebar-section-title">
              {section.title}
            </div>

            <div className="sidebar-section-links">
              {section.links.map((link) => {
                const Icon = link.icon;
                return (
                  <NavLink
                    key={link.to}
                    to={link.to}
                    className={({ isActive }) =>
                      isActive ? "sidebar-link active" : "sidebar-link"
                    }
                  >
                    <Icon size={18} className="sidebar-link-icon" />
                    <span>{link.label}</span>
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
    </aside>
  );
}

export default Sidebar;

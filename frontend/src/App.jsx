import { useState } from "react";

import {
  BrowserRouter,
  Routes,
  Route,
  Link
} from "react-router-dom";

import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  ArrowLeft,
  Search,
  TrendingUp,
  BarChart3,
  Shield,
  Target
} from "lucide-react";

import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line
} from "recharts";

import Navbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";
import StatCard from "./components/StatCard";
import AttackChart from "./components/AttackChart";
import RiskChart from "./components/RiskChart";
import ThreatFilters from "./components/ThreatFilters";
import ThreatTable from "./components/ThreatTable";
import ThreatDetails from "./pages/ThreatDetails";
import AttackSimulation from "./pages/AttackSimulation";
import EnterpriseDashboard from "./pages/EnterpriseDashboard";
import {
  dashboardStats,
  threats,
  attackStatistics,
  riskDistribution
} from "./data/mockData";


/* =========================
   DASHBOARD
========================= */

function Dashboard() {

  return (
    <main className="dashboard-content">

      <div className="dashboard-heading">

        <h1>Security Dashboard</h1>

        <p>
          Monitor API and network threats in real time.
        </p>

      </div>


      {/* Statistics */}

      <div className="stats-grid">

        <StatCard
          title="Total Requests"
          value={dashboardStats.totalRequests}
          description="Requests monitored"
          icon={<Activity size={24} />}
          type="requests"
        />

        <StatCard
          title="Threats Detected"
          value={dashboardStats.threatsDetected}
          description="Potential threats"
          icon={<ShieldAlert size={24} />}
          type="threats"
        />

        <StatCard
          title="Critical Threats"
          value={dashboardStats.criticalThreats}
          description="Require attention"
          icon={<AlertTriangle size={24} />}
          type="critical"
        />

        <StatCard
          title="Blocked Threats"
          value={dashboardStats.blockedThreats}
          description="Threats blocked"
          icon={<ShieldCheck size={24} />}
          type="blocked"
        />

      </div>


      {/* Attack Statistics */}

      <AttackChart
        data={attackStatistics}
      />


      {/* Risk Distribution */}

      <RiskChart
        data={riskDistribution}
      />

    </main>
  );
}


/* =========================
   THREATS PAGE
========================= */

function ThreatsPage() {

  const [attackType, setAttackType] = useState("ALL");
  const [severity, setSeverity] = useState("ALL");
  const [action, setAction] = useState("ALL");
  const [search, setSearch] = useState("");


  const filteredThreats = threats.filter((threat) => {

    const matchesAttack =
      attackType === "ALL" ||
      threat.attackType === attackType;

    const matchesSeverity =
      severity === "ALL" ||
      threat.severity === severity;

    const matchesAction =
      action === "ALL" ||
      threat.action === action;

    const searchText = search.toLowerCase();

    const matchesSearch =
      search === "" ||
      threat.id.toLowerCase().includes(searchText) ||
      threat.sourceIp.toLowerCase().includes(searchText) ||
      threat.attackType.toLowerCase().includes(searchText);

    return (
      matchesAttack &&
      matchesSeverity &&
      matchesAction &&
      matchesSearch
    );
  });


  const resetFilters = () => {

    setAttackType("ALL");
    setSeverity("ALL");
    setAction("ALL");
    setSearch("");

  };


  return (
    <main className="page-content">

      <div className="page-header">

        <div>

          <Link
            to="/"
            className="back-link"
          >
            <ArrowLeft size={16} />
            Dashboard
          </Link>

          <h1>Threats</h1>

          <p>
            View and investigate all detected security threats.
          </p>

        </div>

        <div className="threat-count">
          {filteredThreats.length} threats
        </div>

      </div>


      {/* Search */}

      <div className="search-box">

        <Search size={18} />

        <input
          type="text"
          placeholder="Search by threat ID, IP address, or attack type..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

      </div>


      {/* Filters */}

      <ThreatFilters
        attackType={attackType}
        severity={severity}
        action={action}

        onAttackTypeChange={setAttackType}
        onSeverityChange={setSeverity}
        onActionChange={setAction}

        onReset={resetFilters}
      />


      {/* Table */}

      <ThreatTable
        threats={filteredThreats}
      />

    </main>
  );
}


/* =========================
   ANALYTICS PAGE
========================= */

function AnalyticsPage() {

  const trafficTrend = [
    {
      time: "10:00",
      requests: 1200,
      threats: 8
    },
    {
      time: "11:00",
      requests: 1800,
      threats: 15
    },
    {
      time: "12:00",
      requests: 2100,
      threats: 21
    },
    {
      time: "13:00",
      requests: 1700,
      threats: 17
    },
    {
      time: "14:00",
      requests: 2400,
      threats: 28
    },
    {
      time: "15:00",
      requests: 2600,
      threats: 31
    },
    {
      time: "16:00",
      requests: 2740,
      threats: 7
    }
  ];


  const totalAttacks = attackStatistics.reduce(
    (total, item) => total + item.count,
    0
  );


  const totalRiskEvents = riskDistribution.reduce(
    (total, item) => total + item.count,
    0
  );


  const criticalRisk =
    riskDistribution.find(
      (item) => item.name === "CRITICAL"
    )?.count || 0;


  const highRisk =
    riskDistribution.find(
      (item) => item.name === "HIGH"
    )?.count || 0;


  return (
    <main className="page-content">

      {/* Header */}

      <div className="page-header">

        <div>

          <Link
            to="/"
            className="back-link"
          >
            <ArrowLeft size={16} />
            Dashboard
          </Link>

          <h1>Analytics</h1>

          <p>
            Analyze attack patterns, traffic and security risks.
          </p>

        </div>

      </div>


      {/* Analytics Summary */}

      <div className="analytics-summary">

        <div className="analytics-card">

          <div className="analytics-icon analytics-blue">
            <BarChart3 size={24} />
          </div>

          <div>
            <span>Total Attack Events</span>
            <strong>{totalAttacks}</strong>
          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-icon analytics-red">
            <AlertTriangle size={24} />
          </div>

          <div>
            <span>Critical Events</span>
            <strong>{criticalRisk}</strong>
          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-icon analytics-orange">
            <Target size={24} />
          </div>

          <div>
            <span>High Risk Events</span>
            <strong>{highRisk}</strong>
          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-icon analytics-green">
            <Shield size={24} />
          </div>

          <div>
            <span>Risk Events</span>
            <strong>{totalRiskEvents}</strong>
          </div>

        </div>

      </div>


      {/* Traffic Trend */}

      <div className="analytics-chart-card">

        <div className="analytics-chart-header">

          <div>
            <h2>Traffic & Threat Trend</h2>

            <p>
              Requests and detected threats over time
            </p>
          </div>

          <TrendingUp size={22} />

        </div>


        <ResponsiveContainer
          width="100%"
          height={320}
        >

          <LineChart data={trafficTrend}>

            <CartesianGrid
              stroke="#252d4a"
              strokeDasharray="3 3"
              vertical={false}
            />

            <XAxis
              dataKey="time"
              tick={{
                fill: "#a5acc5",
                fontSize: 12
              }}
              axisLine={{
                stroke: "#303858"
              }}
              tickLine={false}
            />

            <YAxis
              tick={{
                fill: "#a5acc5",
                fontSize: 12
              }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip
              contentStyle={{
                backgroundColor: "#11172a",
                border: "1px solid #39446f",
                borderRadius: "10px",
                color: "#f5f7ff"
              }}
              labelStyle={{
                color: "#ffffff"
              }}
              itemStyle={{
                color: "#c4b5fd"
              }}
            />

            <Line
              type="monotone"
              dataKey="requests"
              stroke="#06B6D4"
              strokeWidth={3}
              name="Requests"
              dot={{
                r: 4,
                fill: "#06B6D4"
              }}
              activeDot={{
                r: 6
              }}
            />

            <Line
              type="monotone"
              dataKey="threats"
              stroke="#EF4444"
              strokeWidth={3}
              name="Threats"
              dot={{
                r: 4,
                fill: "#EF4444"
              }}
              activeDot={{
                r: 6
              }}
            />

          </LineChart>

        </ResponsiveContainer>

      </div>


      {/* Attack Distribution */}

      <div className="analytics-chart-card">

        <div className="analytics-chart-header">

          <div>
            <h2>Attack Distribution</h2>

            <p>
              Number of detected attacks by category
            </p>
          </div>

          <BarChart3 size={22} />

        </div>


        <ResponsiveContainer
          width="100%"
          height={320}
        >

          <BarChart
            data={attackStatistics}
          >

            <CartesianGrid
              stroke="#252d4a"
              strokeDasharray="3 3"
              vertical={false}
            />

            <XAxis
              dataKey="name"
              tick={{
                fill: "#a5acc5",
                fontSize: 13
              }}
              axisLine={{
                stroke: "#303858"
              }}
              tickLine={false}
            />

            <YAxis
              tick={{
                fill: "#a5acc5",
                fontSize: 12
              }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip
              contentStyle={{
                backgroundColor: "#11172a",
                border: "1px solid #39446f",
                borderRadius: "10px",
                color: "#f5f7ff",
                boxShadow: "0 8px 25px rgba(0, 0, 0, 0.35)"
              }}
              labelStyle={{
                color: "#ffffff",
                fontWeight: 600
              }}
              itemStyle={{
                color: "#c4b5fd"
              }}
              cursor={{
                fill: "rgba(99, 102, 241, 0.08)"
              }}
            />

            <Bar
              dataKey="count"
              radius={[8, 8, 0, 0]}
            >

              {attackStatistics.map((entry, index) => {

                const colors = [
                  "#3B82F6",
                  "#8B5CF6",
                  "#06B6D4",
                  "#EC4899",
                  "#F59E0B",
                  "#22C55E",
                  "#EF4444",
                  "#14B8A6",
                  "#6366F1",
                  "#F97316"
                ];

                return (
                  <Cell
                    key={`cell-${index}`}
                    fill={colors[index % colors.length]}
                  />
                );

              })}

            </Bar>

          </BarChart>

        </ResponsiveContainer>

      </div>


      {/* Risk Analysis */}

      <div className="analytics-bottom-grid">

        <div className="analytics-info-card">

          <h2>Risk Overview</h2>

          <div className="risk-row">

            <span>Critical</span>

            <strong>
              {criticalRisk}
            </strong>

          </div>

          <div className="risk-row">

            <span>High</span>

            <strong>
              {highRisk}
            </strong>

          </div>

          <div className="risk-row">

            <span>Medium</span>

            <strong>
              {
                riskDistribution.find(
                  (item) => item.name === "MEDIUM"
                )?.count || 0
              }
            </strong>

          </div>

          <div className="risk-row">

            <span>Low</span>

            <strong>
              {
                riskDistribution.find(
                  (item) => item.name === "LOW"
                )?.count || 0
              }
            </strong>

          </div>

        </div>


        <div className="analytics-info-card">

          <h2>Security Summary</h2>

          <div className="summary-item">

            <ShieldCheck size={20} />

            <div>

              <strong>
                Threat Monitoring Active
              </strong>

              <p>
                API traffic is being monitored for
                suspicious activity.
              </p>

            </div>

          </div>


          <div className="summary-item">

            <Activity size={20} />

            <div>

              <strong>
                Real-Time Detection
              </strong>

              <p>
                Detected events are analyzed and
                assigned risk levels.
              </p>

            </div>

          </div>

        </div>

      </div>

    </main>
  );
}


/* =========================
   MAIN LAYOUT
========================= */

function Layout({ children }) {

  return (
    <div className="app">

      <Sidebar />

      <div className="main-content">

        <Navbar />

        {children}

      </div>

    </div>
  );
}


/* =========================
   ROUTES
========================= */

function App() {

  return (
    <BrowserRouter>

      <Routes>
        <Route
  path="/enterprise"
  element={
    <Layout>
      <EnterpriseDashboard />
    </Layout>
  }
/>
        <Route
          path="/"
          element={
            <Layout>
              <Dashboard />
            </Layout>
          }
        />

        <Route
          path="/threats"
          element={
            <Layout>
              <ThreatsPage />
            </Layout>
          }
        />

        <Route
          path="/analytics"
          element={
            <Layout>
              <AnalyticsPage />
            </Layout>
          }
        />

        <Route
          path="/threat/:id"
          element={
            <Layout>
              <ThreatDetails />
            </Layout>
          }
        />

        <Route
          path="/attack-simulation"
          element={
            <Layout>
              <AttackSimulation />
            </Layout>
          }
        />

      </Routes>

    </BrowserRouter>
  );
}


export default App;
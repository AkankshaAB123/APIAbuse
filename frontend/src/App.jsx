import { useEffect, useState } from "react";
import APISecurityCheck from "./pages/APISecurityCheck";
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
  Target,
  Bot,
  Plus,
  Eye
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
import LoginPage from "./pages/LoginPage";
import NewSecurityTest from "./pages/NewSecurityTest";
import AlertsPage from "./pages/AlertsPage";
import ApiInventory from "./pages/ApiInventory";
import AICopilotPage from "./pages/AICopilotPage";

import {
  getThreats,
  getStatistics
} from "./services/api";
import { formatAttackType } from "./data/attackTypes";
import { isAdmin, ROLE_LABELS } from "./data/roles";
import { AccessRestricted } from "./components/States";


/* =========================================================
   HELPER
========================================================= */

function buildAttackStatistics(threats) {

  const counts = {};

  threats.forEach((threat) => {

    const types =
      Array.isArray(threat.attackTypes) &&
      threat.attackTypes.length > 0
        ? threat.attackTypes
        : threat.attackType
          ? [threat.attackType]
          : [];

    types.forEach((type) => {

      if (!type) {
        return;
      }

      counts[type] =
        (counts[type] || 0) + 1;

    });

  });

  return Object.entries(counts)
    .map(([name, count]) => ({
      name,
      count
    }))
    .sort(
      (a, b) =>
        b.count - a.count
    );
}


/* =========================================================
   DASHBOARD
========================================================= */

function Dashboard({ user }) {

  const [
    statistics,
    setStatistics
  ] = useState(null);

  const [
    threats,
    setThreats
  ] = useState([]);

  const [
    loading,
    setLoading
  ] = useState(true);

  const [
    error,
    setError
  ] = useState("");


  /* =======================================================
     LOAD REAL DASHBOARD DATA
  ======================================================= */

  const loadDashboard = async () => {

    try {

      setLoading(true);

      setError("");

      const [
        stats,
        threatData
      ] = await Promise.all([

        getStatistics(),

        getThreats()

      ]);

      setStatistics(
        stats
      );

      setThreats(
        Array.isArray(threatData)
          ? threatData
          : []
      );

    }

    catch (err) {

      console.error(
        "Failed to load dashboard:",
        err
      );

      setError(
        err.message ||
        "Failed to load dashboard data."
      );

    }

    finally {

      setLoading(false);

    }

  };


  useEffect(() => {

    loadDashboard();

  }, []);


  /* =======================================================
     REAL STATISTICS
  ======================================================= */

  const totalRequests =
    Number(
      statistics?.totalEvents ??
      0
    );

  const threatsDetected =
    Number(
      statistics?.totalThreats ??
      0
    );

  const criticalThreats =
    Number(
      statistics?.criticalThreats ??
      0
    );

  const blockedThreats =
    Number(
      statistics?.blockedThreats ??
      0
    );


  /* =======================================================
     ATTACK DISTRIBUTION
  ======================================================= */

  const attackStatistics =
    buildAttackStatistics(
      threats
    );


  /* =======================================================
     RISK DISTRIBUTION
  ======================================================= */

  const riskDistribution = [

    {
      name: "LOW",
      count: Number(
        statistics?.lowThreats ?? 0
      )
    },

    {
      name: "MEDIUM",
      count: Number(
        statistics?.mediumThreats ?? 0
      )
    },

    {
      name: "HIGH",
      count: Number(
        statistics?.highThreats ?? 0
      )
    },

    {
      name: "CRITICAL",
      count: Number(
        statistics?.criticalThreats ?? 0
      )
    }

  ];


  /* =======================================================
     REAL TRAFFIC TREND
  ======================================================= */

  const trafficTrend =
    Array.isArray(
      statistics?.trafficTrend
    )
      ? statistics.trafficTrend
      : [];


  /* =======================================================
     LOADING
  ======================================================= */

  if (loading) {

    return (

      <main className="dashboard-content">

        <div className="dashboard-heading">

          <h1>
            Security Dashboard
          </h1>

          <p>
            Monitor API and network threats in real time.
          </p>

        </div>

        <div
          className="placeholder-text"
          style={{
            padding: "60px",
            textAlign: "center"
          }}
        >

          Loading security data
          from MongoDB...

        </div>

      </main>

    );

  }


  /* =======================================================
     ERROR
  ======================================================= */

  if (error) {

    return (

      <main className="dashboard-content">

        <div className="dashboard-heading">

          <h1>
            Security Dashboard
          </h1>

          <p>
            Monitor API and network threats in real time.
          </p>

        </div>

        <div
          className="placeholder-text"
          style={{
            padding: "60px",
            textAlign: "center"
          }}
        >

          <strong>
            Unable to load security data
          </strong>

          <br />

          <span>
            {error}
          </span>

          <br />
          <br />

          <button
            className="view-threat-button"
            onClick={
              loadDashboard
            }
          >
            RETRY
          </button>

        </div>

      </main>

    );

  }


  /* =======================================================
     DASHBOARD UI
  ======================================================= */

  return (

    <main className="dashboard-content">

      {/* =================================================
          HEADER
      ================================================= */}

      <div className="dashboard-heading">

        <h1>
          Security Dashboard
        </h1>

        <p>
          Monitor API and network threats in real time.
        </p>

      </div>

      <div className="dashboard-action-bar">
        {isAdmin(user) && (
          <Link className="primary-action" to="/security-test">
            <Plus size={17} />
            NEW SECURITY TEST
          </Link>
        )}
        <Link className="secondary-action" to="/ai-copilot">
          <Bot size={17} />
          ASK SECURITY AI
        </Link>
        <Link className="secondary-action" to="/threats">
          <Eye size={17} />
          VIEW THREATS
        </Link>
      </div>


      {/* =================================================
          REAL STATISTICS
      ================================================= */}

      <div className="stats-grid">

        <StatCard

          title="Total Requests"

          value={
            totalRequests
          }

          description="Events monitored"

          icon={
            <Activity size={24} />
          }

          type="requests"

        />


        <StatCard

          title="Threats Detected"

          value={
            threatsDetected
          }

          description="Potential threats"

          icon={
            <ShieldAlert size={24} />
          }

          type="threats"

        />


        <StatCard

          title="Critical Threats"

          value={
            criticalThreats
          }

          description="Require attention"

          icon={
            <AlertTriangle size={24} />
          }

          type="critical"

        />


        <StatCard

          title="Blocked Threats"

          value={
            blockedThreats
          }

          description="Threats blocked"

          icon={
            <ShieldCheck size={24} />
          }

          type="blocked"

        />

      </div>


      {/* =================================================
          REAL ATTACK STATISTICS
      ================================================= */}

      <AttackChart
        data={
          attackStatistics
        }
      />


      {/* =================================================
          REAL RISK DISTRIBUTION
      ================================================= */}

      <RiskChart
        data={
          riskDistribution
        }
      />

      <div className="dashboard-soc-grid">
        <section className="information-card">
          <div className="section-header">
            <h2>Recent Critical Threats</h2>
            <Link className="table-action-link" to="/alerts">VIEW ALERTS</Link>
          </div>
          {threats.filter((threat) => threat.severity === "CRITICAL").slice(0, 4).length === 0 ? (
            <p className="placeholder-text">No critical threats found.</p>
          ) : (
            threats.filter((threat) => threat.severity === "CRITICAL").slice(0, 4).map((threat) => (
              <Link className="mini-threat-row" key={threat.id} to={`/threat/${threat.id}`}>
                <span>{formatAttackType(threat.attackType)}</span>
                <strong>{threat.riskScore}</strong>
              </Link>
            ))
          )}
        </section>

        <section className="information-card">
          <div className="section-header">
            <h2>Security Activity</h2>
            <span>Live</span>
          </div>
          <div className="information-row"><span>Current Risk Level</span><strong>{criticalThreats > 0 ? "CRITICAL" : threatsDetected > 0 ? "ELEVATED" : "LOW"}</strong></div>
          <div className="information-row"><span>Detection Status</span><strong>ACTIVE</strong></div>
          <div className="information-row"><span>Blocked Threats</span><strong>{blockedThreats}</strong></div>
          <div className="information-row"><span>Analyzed Requests</span><strong>{totalRequests}</strong></div>
        </section>
      </div>


      {/* =================================================
          REAL TRAFFIC TREND
      ================================================= */}

      <div
        className="analytics-chart-card"
        style={{
          marginTop: "24px"
        }}
      >

        <div className="analytics-chart-header">

          <div>

            <h2>
              Traffic & Threat Trend
            </h2>

            <p>
              Requests and detected threats over time
            </p>

          </div>

          <TrendingUp size={22} />

        </div>


        {
          trafficTrend.length === 0 ? (

            <div
              className="placeholder-text"
              style={{
                padding: "60px",
                textAlign: "center"
              }}
            >

              No traffic data available yet.

            </div>

          ) : (

            <ResponsiveContainer
              width="100%"
              height={320}
            >

              <LineChart
                data={trafficTrend}
              >

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

          )
        }

      </div>


      {/* =================================================
          DASHBOARD DATA STATUS
      ================================================= */}

      <div
        style={{
          marginTop: "18px",
          display: "flex",
          justifyContent: "flex-end"
        }}
      >

        <span
          style={{
            fontSize: "12px",
            color: "#7f8db5"
          }}
        >

          ● Live security statistics from MongoDB

        </span>

      </div>

    </main>

  );
}


/* =========================================================
   THREATS PAGE
========================================================= */

function ThreatsPage() {

  const [
    attackType,
    setAttackType
  ] = useState("ALL");

  const [
    severity,
    setSeverity
  ] = useState("ALL");

  const [
    action,
    setAction
  ] = useState("ALL");

  const [
    search,
    setSearch
  ] = useState("");

  const [
    threats,
    setThreats
  ] = useState([]);

  const [
    loading,
    setLoading
  ] = useState(true);

  const [
    error,
    setError
  ] = useState("");


  const loadThreats = async () => {

    try {

      setLoading(true);

      setError("");

      const data =
        await getThreats();

      setThreats(
        Array.isArray(data)
          ? data
          : []
      );

    }

    catch (err) {

      console.error(
        "Failed to load threats:",
        err
      );

      setError(
        err.message ||
        "Failed to load threats."
      );

    }

    finally {

      setLoading(false);

    }

  };


  useEffect(() => {

    loadThreats();

  }, []);


  const filteredThreats =
    threats.filter(
      (threat) => {

        const matchesAttack =
          attackType === "ALL" ||
          threat.attackType ===
            attackType;

        const matchesSeverity =
          severity === "ALL" ||
          threat.severity ===
            severity;

        const matchesAction =
          action === "ALL" ||
          threat.action ===
            action;

        const searchText =
          search.toLowerCase();

        const threatId =
          String(
            threat.id || ""
          ).toLowerCase();

        const sourceIp =
          String(
            threat.sourceIp || ""
          ).toLowerCase();

        const attackName =
          String(
            threat.attackType || ""
          ).toLowerCase();

        const endpoint =
          String(
            threat.endpoint || ""
          ).toLowerCase();

        const matchesSearch =
          search === "" ||
          threatId.includes(
            searchText
          ) ||
          sourceIp.includes(
            searchText
          ) ||
          attackName.includes(
            searchText
          ) ||
          endpoint.includes(
            searchText
          );

        return (
          matchesAttack &&
          matchesSeverity &&
          matchesAction &&
          matchesSearch
        );

      }
    );


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

          <h1>
            Threats
          </h1>

          <p>
            View and investigate all detected security threats.
          </p>

        </div>

        <div className="threat-count">

          {
            loading
              ? "Loading..."
              : `${filteredThreats.length} threats`
          }

        </div>

      </div>


      <div className="search-box">

        <Search size={18} />

        <input

          type="text"

          placeholder="Search by threat ID, IP address, attack type, or endpoint..."

          value={search}

          onChange={(e) =>
            setSearch(
              e.target.value
            )
          }

        />

      </div>


      <ThreatFilters

        attackType={
          attackType
        }

        severity={
          severity
        }

        action={
          action
        }

        onAttackTypeChange={
          setAttackType
        }

        onSeverityChange={
          setSeverity
        }

        onActionChange={
          setAction
        }

        onReset={
          resetFilters
        }

      />


      {
        loading && (

          <div
            className="placeholder-text"
            style={{
              padding: "40px",
              textAlign: "center"
            }}
          >

            Loading threats from MongoDB...

          </div>

        )
      }


      {
        !loading &&
        error && (

          <div
            className="placeholder-text"
            style={{
              padding: "40px",
              textAlign: "center"
            }}
          >

            <strong>
              Unable to load threats
            </strong>

            <br />

            <span>
              {error}
            </span>

            <br />
            <br />

            <button
              className="view-threat-button"
              onClick={
                loadThreats
              }
            >
              RETRY
            </button>

          </div>

        )
      }


      {
        !loading &&
        !error &&
        filteredThreats.length === 0 && (

          <div
            className="placeholder-text"
            style={{
              padding: "40px",
              textAlign: "center"
            }}
          >

            <strong>
              No threats found
            </strong>

            <br />

            <span>
              Run an attack simulation to generate
              a real threat event.
            </span>

          </div>

        )
      }


      {
        !loading &&
        !error &&
        filteredThreats.length > 0 && (

          <ThreatTable
            threats={
              filteredThreats
            }
          />

        )
      }

    </main>

  );
}


/* =========================================================
   ANALYTICS PAGE
========================================================= */

function AnalyticsPage() {

  const [
    statistics,
    setStatistics
  ] = useState(null);

  const [
    analyticsThreats,
    setAnalyticsThreats
  ] = useState([]);

  const [
    analyticsLoading,
    setAnalyticsLoading
  ] = useState(true);

  const [
    analyticsError,
    setAnalyticsError
  ] = useState("");


  useEffect(() => {

    const loadAnalytics =
      async () => {

        try {

          setAnalyticsLoading(
            true
          );

          setAnalyticsError("");

          const [
            stats,
            threatData
          ] = await Promise.all([

            getStatistics(),

            getThreats()

          ]);

          setStatistics(
            stats
          );

          setAnalyticsThreats(
            Array.isArray(
              threatData
            )
              ? threatData
              : []
          );

        }

        catch (err) {

          console.error(
            "Failed to load analytics:",
            err
          );

          setAnalyticsError(
            err.message ||
            "Failed to load analytics data."
          );

        }

        finally {

          setAnalyticsLoading(
            false
          );

        }

      };

    loadAnalytics();

  }, []);


  const totalAttackEvents =
    Number(
      statistics?.totalThreats ??
      0
    );


  const criticalEvents =
    Number(
      statistics?.criticalThreats ??
      0
    );


  const highRiskEvents =
    Number(
      statistics?.highThreats ??
      0
    );


  const mediumRiskEvents =
    Number(
      statistics?.mediumThreats ??
      0
    );


  const lowRiskEvents =
    Number(
      statistics?.lowThreats ??
      0
    );


  const totalRiskEvents =
    criticalEvents +
    highRiskEvents +
    mediumRiskEvents +
    lowRiskEvents;


  const attackCounts = {};


  analyticsThreats.forEach(
    (threat) => {

      const types =
        Array.isArray(
          threat.attackTypes
        ) &&
        threat.attackTypes.length > 0

          ? threat.attackTypes

          : threat.attackType
            ? [threat.attackType]
            : [];


      types.forEach(
        (type) => {

          if (!type) {
            return;
          }

          attackCounts[type] =
            (attackCounts[type] || 0) +
            1;

        }
      );

    }
  );


  const displayAttackStatistics =
    Object.entries(
      attackCounts
    )
      .map(
        ([name, count]) => ({
          name,
          count
        })
      )
      .sort(
        (a, b) =>
          b.count - a.count
      );


  /* =======================================================
     REAL TRAFFIC TREND
  ======================================================= */

  const trafficTrend =
    Array.isArray(
      statistics?.trafficTrend
    )
      ? statistics.trafficTrend
      : [];


  if (analyticsLoading) {

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

            <h1>
              Analytics
            </h1>

            <p>
              Analyze attack patterns,
              traffic and security risks.
            </p>

          </div>

        </div>


        <div
          className="placeholder-text"
          style={{
            padding: "60px",
            textAlign: "center"
          }}
        >

          Loading real analytics
          from MongoDB...

        </div>

      </main>

    );

  }


  if (analyticsError) {

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

            <h1>
              Analytics
            </h1>

            <p>
              Analyze attack patterns,
              traffic and security risks.
            </p>

          </div>

        </div>


        <div
          className="placeholder-text"
          style={{
            padding: "60px",
            textAlign: "center"
          }}
        >

          <strong>
            Unable to load analytics
          </strong>

          <br />

          <span>
            {analyticsError}
          </span>

        </div>

      </main>

    );

  }


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

          <h1>
            Analytics
          </h1>

          <p>
            Analyze attack patterns,
            traffic and security risks.
          </p>

        </div>

      </div>


      <div className="analytics-summary">

        <div className="analytics-card">

          <div className="analytics-icon analytics-blue">

            <BarChart3 size={24} />

          </div>

          <div>

            <span>
              Total Attack Events
            </span>

            <strong>
              {totalAttackEvents}
            </strong>

          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-icon analytics-red">

            <AlertTriangle size={24} />

          </div>

          <div>

            <span>
              Critical Events
            </span>

            <strong>
              {criticalEvents}
            </strong>

          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-icon analytics-orange">

            <Target size={24} />

          </div>

          <div>

            <span>
              High Risk Events
            </span>

            <strong>
              {highRiskEvents}
            </strong>

          </div>

        </div>


        <div className="analytics-card">

          <div className="analytics-icon analytics-green">

            <Shield size={24} />

          </div>

          <div>

            <span>
              Risk Events
            </span>

            <strong>
              {totalRiskEvents}
            </strong>

          </div>

        </div>

      </div>


      {/* =================================================
          REAL TRAFFIC & THREAT TREND
      ================================================= */}

      <div className="analytics-chart-card">

        <div className="analytics-chart-header">

          <div>

            <h2>
              Traffic & Threat Trend
            </h2>

            <p>
              Requests and detected threats over time
            </p>

          </div>

          <TrendingUp size={22} />

        </div>


        {
          trafficTrend.length === 0 ? (

            <div
              className="placeholder-text"
              style={{
                padding: "60px",
                textAlign: "center"
              }}
            >

              No traffic data available yet.

            </div>

          ) : (

            <ResponsiveContainer
              width="100%"
              height={320}
            >

              <LineChart
                data={trafficTrend}
              >

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

          )
        }

      </div>


      {/* =================================================
          ATTACK DISTRIBUTION
      ================================================= */}

      <div className="analytics-chart-card">

        <div className="analytics-chart-header">

          <div>

            <h2>
              Attack Distribution
            </h2>

            <p>
              Number of detected attacks by category
            </p>

          </div>

          <BarChart3 size={22} />

        </div>


        {
          displayAttackStatistics.length === 0 ? (

            <div
              className="placeholder-text"
              style={{
                padding: "60px",
                textAlign: "center"
              }}
            >

              No attack distribution data
              available yet.

            </div>

          ) : (

            <ResponsiveContainer
              width="100%"
              height={320}
            >

              <BarChart
                data={
                  displayAttackStatistics
                }
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
                  allowDecimals={false}
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
                    color: "#ffffff",
                    fontWeight: 600
                  }}
                  itemStyle={{
                    color: "#c4b5fd"
                  }}
                  cursor={{
                    fill:
                      "rgba(99, 102, 241, 0.08)"
                  }}
                />


                <Bar
                  dataKey="count"
                  radius={[
                    8,
                    8,
                    0,
                    0
                  ]}
                >

                  {
                    displayAttackStatistics.map(
                      (
                        entry,
                        index
                      ) => {

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
                            key={
                              `cell-${index}`
                            }
                            fill={
                              colors[
                                index %
                                colors.length
                              ]
                            }
                          />

                        );

                      }
                    )
                  }

                </Bar>

              </BarChart>

            </ResponsiveContainer>

          )
        }

      </div>


      {/* =================================================
          RISK / SECURITY SUMMARY
      ================================================= */}

      <div className="analytics-bottom-grid">

        <div className="analytics-info-card">

          <h2>
            Risk Overview
          </h2>


          <div className="risk-row">

            <span>
              Critical
            </span>

            <strong>
              {criticalEvents}
            </strong>

          </div>


          <div className="risk-row">

            <span>
              High
            </span>

            <strong>
              {highRiskEvents}
            </strong>

          </div>


          <div className="risk-row">

            <span>
              Medium
            </span>

            <strong>
              {mediumRiskEvents}
            </strong>

          </div>


          <div className="risk-row">

            <span>
              Low
            </span>

            <strong>
              {lowRiskEvents}
            </strong>

          </div>

        </div>


        <div className="analytics-info-card">

          <h2>
            Security Summary
          </h2>


          <div className="summary-item">

            <ShieldCheck size={20} />

            <div>

              <strong>
                Threat Monitoring Active
              </strong>

              <p>
                API traffic is being monitored
                for suspicious activity.
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
                Detected events are analyzed
                and assigned risk levels.
              </p>

            </div>

          </div>

        </div>

      </div>

    </main>

  );
}


/* =========================================================
   MAIN LAYOUT
========================================================= */

function Layout({
  children,
  user,
  onLogout
}) {

  return (

    <div className="app">

      <Sidebar user={user} />

      <div className="main-content">

        <Navbar
          user={user}
          onLogout={onLogout}
        />

        {children}

      </div>

    </div>

  );
}


/* =========================================================
   APP ROUTES
========================================================= */

function App() {
  const [user, setUser] = useState(() => {
    const storedUser = localStorage.getItem("threatguardUser");
    return storedUser ? JSON.parse(storedUser) : null;
  });

  const login = (nextUser) => {
    localStorage.setItem("threatguardUser", JSON.stringify(nextUser));
    setUser(nextUser);
  };

  const logout = () => {
    localStorage.removeItem("threatguardUser");
    setUser(null);
  };

  const shell = (children) => (
    <Layout user={user} onLogout={logout}>
      {children}
    </Layout>
  );

  const adminShell = (children) =>
    isAdmin(user)
      ? shell(children)
      : shell(
          <AccessRestricted
            role={ROLE_LABELS[user?.role] || "Security Analyst"}
          />
        );

  return (

    <BrowserRouter>

      <Routes>
        {!user && (
          <Route
            path="*"
            element={<LoginPage onLogin={login} />}
          />
        )}

        {user && (
          <>

        <Route
          path="/"
          element={
            shell(<Dashboard user={user} />)

          }
        />


        <Route
          path="/threats"
          element={
            shell(<ThreatsPage />)

          }
        />


        <Route
          path="/analytics"
          element={
            shell(<AnalyticsPage />)

          }
        />


        <Route
          path="/threat/:id"
          element={
            shell(<ThreatDetails />)

          }
        />


        <Route
          path="/attack-simulation"
          element={
            adminShell(<AttackSimulation />)

          }
        />

        <Route
          path="/enterprise"
          element={
            adminShell(<EnterpriseDashboard />)

          }
        />
        <Route
          path="/api-security-check"
          element={
            shell(<APISecurityCheck />)
          }
        />

        <Route
          path="/security-test"
          element={
            adminShell(<NewSecurityTest />)
          }
        />

        <Route
          path="/alerts"
          element={
            shell(<AlertsPage />)
          }
        />

        <Route
          path="/api-inventory"
          element={
            shell(<ApiInventory />)
          }
        />

        <Route
          path="/ai-copilot"
          element={
            shell(<AICopilotPage />)
          }
        />

          </>
        )}
      </Routes>

    </BrowserRouter>

  );
}


export default App;

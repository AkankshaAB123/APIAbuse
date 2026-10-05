import { useEffect, useState } from "react";

import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  TrendingUp,
  Clock,
  ArrowUpRight
} from "lucide-react";

import {
  getThreats,
  getStatistics
} from "../services/api";


function EnterpriseDashboard() {

  const [statistics, setStatistics] = useState(null);

  const [threats, setThreats] = useState([]);

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState("");


  /* =========================================================
     LOAD REAL ENTERPRISE DATA
  ========================================================= */

  const loadEnterpriseData = async () => {

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


      setStatistics(stats);

      setThreats(
        Array.isArray(threatData)
          ? threatData
          : []
      );

    }

    catch (err) {

      console.error(
        "Failed to load enterprise dashboard:",
        err
      );

      setError(
        err.message ||
        "Failed to load enterprise security data."
      );

    }

    finally {

      setLoading(false);

    }

  };


  useEffect(() => {

    loadEnterpriseData();

  }, []);


  /* =========================================================
     REAL STATISTICS
  ========================================================= */

  const totalRequests =
    Number(
      statistics?.totalEvents ?? 0
    );


  const threatsDetected =
    Number(
      statistics?.totalThreats ?? 0
    );


  const criticalThreats =
    Number(
      statistics?.criticalThreats ?? 0
    );


  const blockedThreats =
    Number(
      statistics?.blockedThreats ?? 0
    );


  /* =========================================================
     RECENT THREATS
  ========================================================= */

  const recentThreats =
    threats.slice(0, 5);


  /* =========================================================
     FORMAT THREAT TIME
  ========================================================= */

  const formatThreatTime = (timestamp) => {

    if (!timestamp) {
      return "Unknown time";
    }

    const date =
      new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
      return "Unknown time";
    }

    return date.toLocaleString(
      undefined,
      {
        dateStyle: "short",
        timeStyle: "short"
      }
    );

  };


  /* =========================================================
     LOADING STATE
  ========================================================= */

  if (loading) {

    return (

      <main className="page-content">

        <div className="page-header">

          <div>

            <div className="page-kicker">
              ENTERPRISE SECURITY
            </div>

            <h1>
              API Security Overview
            </h1>

            <p>
              Monitor the security status and threats affecting your API.
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

          Loading enterprise security
          data from MongoDB...

        </div>

      </main>

    );

  }


  /* =========================================================
     ERROR STATE
  ========================================================= */

  if (error) {

    return (

      <main className="page-content">

        <div className="page-header">

          <div>

            <div className="page-kicker">
              ENTERPRISE SECURITY
            </div>

            <h1>
              API Security Overview
            </h1>

            <p>
              Monitor the security status and threats affecting your API.
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
            Unable to load enterprise security data
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
              loadEnterpriseData
            }
          >
            RETRY
          </button>

        </div>

      </main>

    );

  }


  return (

    <main className="page-content">


      {/* =====================================================
          HEADER
      ===================================================== */}

      <div className="page-header">

        <div>

          <div className="page-kicker">
            ENTERPRISE SECURITY
          </div>

          <h1>
            API Security Overview
          </h1>

          <p>
            Monitor the security status and threats affecting your API.
          </p>

        </div>


        <div className="enterprise-status">

          <span className="status-dot"></span>

          PROTECTION ACTIVE

        </div>

      </div>


      {/* =====================================================
          SECURITY STATUS
      ===================================================== */}

      <div className="enterprise-security-banner">

        <div className="enterprise-security-icon">

          <ShieldCheck size={30} />

        </div>


        <div className="enterprise-security-text">

          <h2>
            Your API is protected
          </h2>

          <p>
            API traffic is being monitored for suspicious
            activity and potential abuse.
          </p>

        </div>


        <div className="security-status-badge">
          ACTIVE
        </div>

      </div>


      {/* =====================================================
          REAL STATISTICS
      ===================================================== */}

      <div className="stats-grid">


        <div className="enterprise-stat-card">

          <div className="enterprise-stat-icon enterprise-blue">

            <Activity size={23} />

          </div>


          <div>

            <span>
              Requests Monitored
            </span>

            <strong>
              {totalRequests}
            </strong>

            <small>
              API requests analyzed
            </small>

          </div>

        </div>


        <div className="enterprise-stat-card">

          <div className="enterprise-stat-icon enterprise-red">

            <ShieldAlert size={23} />

          </div>


          <div>

            <span>
              Threats Detected
            </span>

            <strong>
              {threatsDetected}
            </strong>

            <small>
              Suspicious activities found
            </small>

          </div>

        </div>


        <div className="enterprise-stat-card">

          <div className="enterprise-stat-icon enterprise-orange">

            <AlertTriangle size={23} />

          </div>


          <div>

            <span>
              Critical Threats
            </span>

            <strong>
              {criticalThreats}
            </strong>

            <small>
              Require immediate attention
            </small>

          </div>

        </div>


        <div className="enterprise-stat-card">

          <div className="enterprise-stat-icon enterprise-green">

            <ShieldCheck size={23} />

          </div>


          <div>

            <span>
              Blocked Threats
            </span>

            <strong>
              {blockedThreats}
            </strong>

            <small>
              Automatically prevented
            </small>

          </div>

        </div>

      </div>


      {/* =====================================================
          MAIN GRID
      ===================================================== */}

      <div className="enterprise-grid">


        {/* ===================================================
            RECENT THREATS
        =================================================== */}

        <div className="enterprise-card">

          <div className="enterprise-card-header">

            <div>

              <h2>
                Recent Security Alerts
              </h2>

              <p>
                Latest detected API security events
              </p>

            </div>


            <ShieldAlert size={21} />

          </div>


          <div className="enterprise-threat-list">

            {
              recentThreats.length === 0 ? (

                <div
                  className="placeholder-text"
                  style={{
                    padding: "30px",
                    textAlign: "center"
                  }}
                >

                  No detected threats yet.

                </div>

              ) : (

                recentThreats.map(
                  (threat) => (

                    <div
                      className="enterprise-threat-item"
                      key={threat.id}
                    >


                      <div className="enterprise-threat-main">

                        <div className="enterprise-threat-icon">

                          <AlertTriangle size={18} />

                        </div>


                        <div>

                          <strong>
                            {
                              threat.attackType ||
                              "UNKNOWN"
                            }
                          </strong>

                          <span>
                            {
                              threat.sourceIp ||
                              "Unknown source"
                            }
                          </span>

                        </div>

                      </div>


                      <div className="enterprise-threat-meta">


                        <span
                          className={`enterprise-severity ${
                            String(
                              threat.severity ||
                              "UNKNOWN"
                            ).toLowerCase()
                          }`}
                        >

                          {
                            threat.severity ||
                            "UNKNOWN"
                          }

                        </span>


                        <span className="enterprise-threat-time">

                          <Clock size={14} />

                          {
                            formatThreatTime(
                              threat.timestamp
                            )
                          }

                        </span>


                        <ArrowUpRight size={17} />

                      </div>

                    </div>

                  )
                )

              )
            }

          </div>

        </div>


        {/* ===================================================
            SECURITY INSIGHTS
        =================================================== */}

        <div className="enterprise-card">

          <div className="enterprise-card-header">

            <div>

              <h2>
                Security Insights
              </h2>

              <p>
                Current API security observations
              </p>

            </div>


            <TrendingUp size={21} />

          </div>


          <div className="enterprise-insights">


            <div className="enterprise-insight">

              <div className="insight-icon insight-red">

                <AlertTriangle size={18} />

              </div>


              <div>

                <strong>
                  Threat activity detected
                </strong>

                <p>
                  {
                    threatsDetected > 0
                      ? `${threatsDetected} suspicious API events have been detected and analyzed.`
                      : "No suspicious API activity has been detected yet."
                  }
                </p>

              </div>

            </div>


            <div className="enterprise-insight">

              <div className="insight-icon insight-green">

                <ShieldCheck size={18} />

              </div>


              <div>

                <strong>
                  API protection active
                </strong>

                <p>
                  Detected threats are being monitored
                  and mitigation actions are recorded.
                </p>

              </div>

            </div>


            <div className="enterprise-insight">

              <div className="insight-icon insight-purple">

                <TrendingUp size={18} />

              </div>


              <div>

                <strong>
                  AI security analysis
                </strong>

                <p>
                  Detected events can be analyzed using
                  the AI-powered security intelligence layer.
                </p>

              </div>

            </div>

          </div>

        </div>

      </div>


      {/* =====================================================
          API MONITORING
      ===================================================== */}

      <div className="enterprise-card enterprise-monitoring-card">

        <div className="enterprise-card-header">

          <div>

            <h2>
              API Protection Status
            </h2>

            <p>
              Current monitoring components
            </p>

          </div>


          <ShieldCheck size={21} />

        </div>


        <div className="protection-grid">


          <div className="protection-item">

            <span className="protection-dot active"></span>

            <div>

              <strong>
                API Traffic Monitoring
              </strong>

              <p>
                Active
              </p>

            </div>

          </div>


          <div className="protection-item">

            <span className="protection-dot active"></span>

            <div>

              <strong>
                Threat Detection
              </strong>

              <p>
                Active
              </p>

            </div>

          </div>


          <div className="protection-item">

            <span className="protection-dot active"></span>

            <div>

              <strong>
                Risk Assessment
              </strong>

              <p>
                Active
              </p>

            </div>

          </div>


          <div className="protection-item">

            <span className="protection-dot active"></span>

            <div>

              <strong>
                Security Alerts
              </strong>

              <p>
                Active
              </p>

            </div>

          </div>

        </div>

      </div>


      {/* =====================================================
          DATA STATUS
      ===================================================== */}

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

          ● Live enterprise security data from MongoDB

        </span>

      </div>

    </main>

  );

}


export default EnterpriseDashboard;
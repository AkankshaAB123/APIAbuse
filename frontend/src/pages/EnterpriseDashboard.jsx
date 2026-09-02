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
  dashboardStats,
  threats
} from "../data/mockData";

function EnterpriseDashboard() {

  const recentThreats = threats.slice(0, 5);

  return (
    <main className="page-content">

      {/* HEADER */}

      <div className="page-header">

        <div>
          <div className="page-kicker">
            ENTERPRISE SECURITY
          </div>

          <h1>API Security Overview</h1>

          <p>
            Monitor the security status and threats affecting your API.
          </p>
        </div>

        <div className="enterprise-status">
          <span className="status-dot"></span>
          PROTECTION ACTIVE
        </div>

      </div>


      {/* SECURITY STATUS */}

      <div className="enterprise-security-banner">

        <div className="enterprise-security-icon">
          <ShieldCheck size={30} />
        </div>

        <div className="enterprise-security-text">

          <h2>Your API is protected</h2>

          <p>
            API traffic is being monitored for suspicious
            activity and potential abuse.
          </p>

        </div>

        <div className="security-status-badge">
          ACTIVE
        </div>

      </div>


      {/* STATISTICS */}

      <div className="stats-grid">

        <div className="enterprise-stat-card">

          <div className="enterprise-stat-icon enterprise-blue">
            <Activity size={23} />
          </div>

          <div>
            <span>Requests Monitored</span>

            <strong>
              {dashboardStats.totalRequests}
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
            <span>Threats Detected</span>

            <strong>
              {dashboardStats.threatsDetected}
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
            <span>Critical Threats</span>

            <strong>
              {dashboardStats.criticalThreats}
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
            <span>Blocked Threats</span>

            <strong>
              {dashboardStats.blockedThreats}
            </strong>

            <small>
              Automatically prevented
            </small>
          </div>

        </div>

      </div>


      {/* MAIN GRID */}

      <div className="enterprise-grid">

        {/* RECENT THREATS */}

        <div className="enterprise-card">

          <div className="enterprise-card-header">

            <div>

              <h2>Recent Security Alerts</h2>

              <p>
                Latest detected API security events
              </p>

            </div>

            <ShieldAlert size={21} />

          </div>


          <div className="enterprise-threat-list">

            {recentThreats.map((threat) => (

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
                      {threat.attackType}
                    </strong>

                    <span>
                      {threat.sourceIp}
                    </span>

                  </div>

                </div>


                <div className="enterprise-threat-meta">

                  <span
                    className={`enterprise-severity ${threat.severity.toLowerCase()}`}
                  >
                    {threat.severity}
                  </span>

                  <span className="enterprise-threat-time">
                    <Clock size={14} />
                    {threat.time}
                  </span>

                  <ArrowUpRight size={17} />

                </div>

              </div>

            ))}

          </div>

        </div>


        {/* SECURITY INSIGHTS */}

        <div className="enterprise-card">

          <div className="enterprise-card-header">

            <div>

              <h2>Security Insights</h2>

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
                  Suspicious API requests have been
                  identified and analyzed.
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


      {/* API MONITORING */}

      <div className="enterprise-card enterprise-monitoring-card">

        <div className="enterprise-card-header">

          <div>

            <h2>API Protection Status</h2>

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
              <strong>API Traffic Monitoring</strong>
              <p>Active</p>
            </div>

          </div>


          <div className="protection-item">

            <span className="protection-dot active"></span>

            <div>
              <strong>Threat Detection</strong>
              <p>Active</p>
            </div>

          </div>


          <div className="protection-item">

            <span className="protection-dot active"></span>

            <div>
              <strong>Risk Assessment</strong>
              <p>Active</p>
            </div>

          </div>


          <div className="protection-item">

            <span className="protection-dot active"></span>

            <div>
              <strong>Security Alerts</strong>
              <p>Active</p>
            </div>

          </div>

        </div>

      </div>

    </main>
  );
}

export default EnterpriseDashboard;
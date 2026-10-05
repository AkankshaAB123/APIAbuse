import { useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  Database,
  Globe2,
  KeyRound,
  Lock,
  Play,
  Server,
  ShieldAlert,
  Zap,
} from "lucide-react";
import RiskBadge from "../components/RiskBadge";
import { ErrorState } from "../components/States";
import { formatAttackType } from "../data/attackTypes";
import { launchLabAttack, launchSyntheticPhishingEmail } from "../services/api";

const DEFAULT_PHISHING_EMAIL = {
  target_enterprise: "ThreatGuard Demo Enterprise",
  sender: "security-alert@simulated-login.example.test",
  recipient: "victim_demo@threatguard.example.test",
  subject: "Urgent: Verify your account now",
  email_body:
    "Your account requires verification. Sign in now using https://simulated-login.example.test/verify to avoid suspension.",
  suspicious_url: "https://simulated-login.example.test/verify",
};

const LAB_ATTACKS = [
  {
    id: "bola",
    name: "BOLA / IDOR",
    endpoint: "/lab/attacks/bola",
    description:
      "Attempts to access another synthetic user's protected resource in the controlled lab API.",
    classification: "API -> Authorization -> BOLA / IDOR",
    icon: Lock,
  },
  {
    id: "sql-injection",
    name: "SQL Injection",
    endpoint: "/lab/attacks/sql-injection",
    description:
      "Submits a malicious search input to the vulnerable local product search lab.",
    classification: "API -> Injection -> SQL Injection",
    icon: Database,
  },
  {
    id: "ssrf",
    name: "SSRF",
    endpoint: "/lab/attacks/ssrf",
    description:
      "Forces the vulnerable local fetch target to request a restricted internal lab endpoint.",
    classification: "API -> Server-Side Request -> SSRF",
    icon: Globe2,
  },
  {
    id: "dos-flood",
    name: "DoS / API Flooding",
    endpoint: "/lab/attacks/dos-flood",
    description:
      "Generates a bounded request burst against the controlled local flood target.",
    classification: "NETWORK/API -> Availability -> DoS / API Flooding",
    icon: Zap,
  },
  {
    id: "phishing",
    name: "Phishing",
    endpoint: "/lab/attacks/phishing",
    description:
      "Launches the local fake login page and submits dummy victim credentials.",
    classification: "ENDPOINT -> Social Engineering / Phishing -> Credential Phishing",
    icon: KeyRound,
  },
];

function valueOrNA(value) {
  if (value === undefined || value === null || value === "") {
    return "N/A";
  }

  return typeof value === "object" ? JSON.stringify(value) : value;
}

function formatLifecycle(lifecycle) {
  if (Array.isArray(lifecycle?.states)) {
    return lifecycle.states;
  }

  if (Array.isArray(lifecycle)) {
    return lifecycle;
  }

  return [];
}

function getIncidentId(result) {
  return result?.incident_id || result?.incidentId || result?.event_id || result?.eventId;
}

function getAttackName(result, fallback) {
  return (
    result?.attack?.name ||
    result?.attack_type ||
    result?.attackType ||
    result?.classification?.level3 ||
    fallback
  );
}

function getTarget(result) {
  return (
    result?.attack?.target_endpoint ||
    result?.attack?.requested_resource ||
    result?.attack?.target ||
    result?.target?.endpoint ||
    result?.target ||
    result?.request?.endpoint ||
    result?.metadata?.endpoint
  );
}

function getSourceIp(result) {
  return (
    result?.actual_client_ip ||
    result?.actualClientIp ||
    result?.source_ip ||
    result?.sourceIp ||
    result?.attack?.actual_client_ip ||
    result?.attack?.source_ip
  );
}

function getUser(result) {
  return (
    result?.attack?.email?.recipient ||
    result?.attack?.attacker ||
    result?.attack?.user ||
    result?.attack?.requester ||
    result?.attack?.captured_username ||
    result?.identity?.user_id ||
    result?.user_id ||
    result?.user ||
    result?.attack?.authentication_status
  );
}

function getRisk(result) {
  return result?.risk || result?.risk_assessment || result?.riskAssessment || {};
}

function getMitigation(result) {
  return result?.mitigation || result?.mitigation_result || result?.mitigationResult || {};
}

function getDetection(result) {
  return result?.detection || {};
}

function getImpact(result) {
  return result?.impact || {};
}

function AttackResultPanel({ attack, result }) {
  if (!result) {
    return (
      <div className="console-result-empty">
        Launch this lab to see the actual target response, impact, detection,
        risk, and mitigation returned by the backend.
      </div>
    );
  }

  const risk = getRisk(result);
  const mitigation = getMitigation(result);
  const detection = getDetection(result);
  const impact = getImpact(result);
  const lifecycle = formatLifecycle(result.lifecycle);
  const incidentId = getIncidentId(result);
  const threatLink = incidentId ? `/threat/${incidentId}` : null;

  return (
    <div className="console-result">
      <div className="console-result-topline">
        <div>
          <span>Incident</span>
          <strong>{valueOrNA(incidentId)}</strong>
        </div>

        <RiskBadge
          score={risk.risk_score ?? risk.score ?? result.risk_score ?? result.riskScore ?? "N/A"}
          severity={risk.risk_level ?? risk.level ?? result.risk_level ?? result.riskLevel ?? result.severity}
        />
      </div>

      <div className="console-result-grid">
        <div><span>Attack</span><strong>{formatAttackType(getAttackName(result, attack.name))}</strong></div>
        <div><span>Target</span><strong>{valueOrNA(getTarget(result))}</strong></div>
        <div><span>Source IP</span><strong>{valueOrNA(getSourceIp(result))}</strong></div>
        <div><span>User / Login</span><strong>{valueOrNA(getUser(result))}</strong></div>
        <div><span>Impact</span><strong>{impact.observed ?? result.impact_observed ? "Observed" : "Not observed"}</strong></div>
        <div><span>Detector</span><strong>{valueOrNA(detection.primary_detector || detection.method || detection.detector || result.detector)}</strong></div>
        <div><span>Before HTTP</span><strong>{valueOrNA(impact.target_response_before_mitigation?.status_code ?? impact.before_status ?? result.before_status)}</strong></div>
        <div><span>After HTTP</span><strong>{valueOrNA(mitigation.post_mitigation_response?.status_code ?? mitigation.after_status ?? result.after_status)}</strong></div>
        <div><span>Mitigation</span><strong>{valueOrNA(mitigation.action || result.mitigation_action || result.action)}</strong></div>
        <div><span>Final Status</span><strong>{valueOrNA(result.status || mitigation.result || result.final_status)}</strong></div>
      </div>

      {impact.evidence && (
        <div className="console-evidence">
          <span>Impact Evidence</span>
          <p>{typeof impact.evidence === "string" ? impact.evidence : JSON.stringify(impact.evidence)}</p>
        </div>
      )}

      {lifecycle.length > 0 && (
        <div className="lifecycle-strip">
          {lifecycle.map((state) => (
            <span key={state}>{state}</span>
          ))}
        </div>
      )}

      <div className="console-actions">
        {threatLink && (
          <Link className="secondary-action" to={threatLink}>
            View Incident
          </Link>
        )}
        <Link className="secondary-action" to="/soc-live">
          Open SOC View
        </Link>
      </div>
    </div>
  );
}

function SyntheticPhishingEmailForm({ value, onChange }) {
  const updateField = (field, fieldValue) => {
    onChange({ ...value, [field]: fieldValue });
  };

  return (
    <div className="synthetic-email-composer">
      <div className="composer-heading">
        <span>LIVE SYNTHETIC EMAIL</span>
        <small>Local IDS input only. No SMTP delivery or URL request occurs.</small>
      </div>
      <label>
        Target enterprise
        <select value={value.target_enterprise} onChange={(event) => updateField("target_enterprise", event.target.value)}>
          <option>ThreatGuard Demo Enterprise</option>
          <option>Northstar Labs</option>
          <option>Acme Finance Lab</option>
        </select>
      </label>
      <label>
        Sender
        <input value={value.sender} onChange={(event) => updateField("sender", event.target.value)} />
      </label>
      <label>
        Recipient
        <input value={value.recipient} onChange={(event) => updateField("recipient", event.target.value)} />
      </label>
      <label>
        Subject
        <input value={value.subject} onChange={(event) => updateField("subject", event.target.value)} />
      </label>
      <label>
        Email body
        <textarea rows="4" value={value.email_body} onChange={(event) => updateField("email_body", event.target.value)} />
      </label>
      <label>
        Suspicious URL indicator
        <input value={value.suspicious_url} onChange={(event) => updateField("suspicious_url", event.target.value)} />
      </label>
      <div className="synthetic-email-preview">
        <span>EMAIL PREVIEW</span>
        <strong>From: {value.sender}</strong>
        <strong>To: {value.recipient}</strong>
        <strong>Subject: {value.subject}</strong>
        <p>{value.email_body}</p>
        <code>{value.suspicious_url}</code>
      </div>
    </div>
  );
}

function AttackerConsole() {
  const [attackState, setAttackState] = useState({});
  const [phishingEmail, setPhishingEmail] = useState(DEFAULT_PHISHING_EMAIL);

  const launchAttack = async (attack) => {
    setAttackState((current) => ({
      ...current,
      [attack.id]: {
        status: "ATTACKING",
        result: null,
        error: "",
      },
    }));

    try {
      const result = attack.id === "phishing"
        ? await launchSyntheticPhishingEmail(phishingEmail)
        : await launchLabAttack(attack.endpoint);

      setAttackState((current) => ({
        ...current,
        [attack.id]: {
          status: result?.status || "COMPLETED",
          result,
          error: "",
        },
      }));
    } catch (error) {
      setAttackState((current) => ({
        ...current,
        [attack.id]: {
          status: "FAILED",
          result: null,
          error: error.message || "Unable to launch controlled lab attack.",
        },
      }));
    }
  };

  return (
    <main className="page-content">
      <div className="page-header">
        <div>
          <div className="page-kicker">ATTACKER LAB</div>
          <h1>Attacker Console</h1>
          <p>
            Launch bounded local lab attacks against intentionally vulnerable
            ThreatGuard targets and watch the real backend pipeline respond.
          </p>
        </div>

        <div className="enterprise-status">
          <span className="status-dot"></span>
          LOCAL LAB ONLY
        </div>
      </div>

      <div className="lab-safety-banner">
        <ShieldAlert size={22} />
        <div>
          <strong>Controlled cyber-range mode</strong>
          <p>
            These buttons call the existing local lab endpoints. They do not
            attack external systems or submit frontend-only fake events.
          </p>
        </div>
      </div>

      <section className="attacker-console-grid">
        {LAB_ATTACKS.map((attack) => {
          const Icon = attack.icon;
          const state = attackState[attack.id] || {};
          const isRunning = state.status === "ATTACKING";

          return (
            <article className="attack-launch-card" key={attack.id}>
              <div className="attack-launch-header">
                <div className="attack-launch-icon">
                  <Icon size={22} />
                </div>
                <div>
                  <h2>{attack.name}</h2>
                  <span>{attack.classification}</span>
                </div>
              </div>

              <p>{attack.description}</p>

              {attack.id === "phishing" && (
                <SyntheticPhishingEmailForm
                  value={phishingEmail}
                  onChange={setPhishingEmail}
                />
              )}

              <div className="attack-endpoint">
                <Server size={15} />
                POST {attack.id === "phishing" ? "/lab/attacks/phishing-email" : attack.endpoint}
              </div>

              <div className={`attack-execution-status ${String(state.status || "READY").toLowerCase()}`}>
                <AlertTriangle size={15} />
                {state.status || "READY"}
              </div>

              {state.error && (
                <ErrorState
                  title="Attack launch failed"
                  message={state.error}
                />
              )}

              <AttackResultPanel attack={attack} result={state.result} />

              <button
                className="primary-action attack-launch-button"
                type="button"
                disabled={isRunning}
                onClick={() => launchAttack(attack)}
              >
                <Play size={17} />
                {isRunning ? "Sending..." : attack.id === "phishing" ? "Send Synthetic Email" : "Launch Attack"}
              </button>
            </article>
          );
        })}
      </section>
    </main>
  );
}

export default AttackerConsole;

import { useState } from "react";
import {
  ShieldCheck,
  Eye,
  EyeOff,
  Lock,
  User,
  UserPlus,
  Activity,
  Cpu,
  Database,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { ROLES } from "../data/roles";
import { loginUser, registerUser } from "../services/api";

/* =========================================================
   PASSWORD STRENGTH METER
========================= */

function measureStrength(password) {
  if (!password) return { score: 0, label: "", color: "" };
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;

  if (score <= 1) return { score, label: "Weak", color: "#ef4444" };
  if (score <= 2) return { score, label: "Fair", color: "#f97316" };
  if (score <= 3) return { score, label: "Good", color: "#eab308" };
  if (score <= 4) return { score, label: "Strong", color: "#22c55e" };
  return { score, label: "Very Strong", color: "#10b981" };
}

function PasswordStrengthBar({ password }) {
  const { score, label, color } = measureStrength(password);
  if (!password) return null;
  const pct = Math.round((score / 5) * 100);

  return (
    <div className="password-strength">
      <div className="password-strength-track">
        <div
          className="password-strength-fill"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      <span className="password-strength-label" style={{ color }}>
        {label}
      </span>
    </div>
  );
}

/* =========================================================
   PASSWORD INPUT — with show/hide toggle
========================= */

function PasswordInput({ id, value, onChange, placeholder, autoComplete }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="password-field">
      <input
        id={id}
        type={visible ? "text" : "password"}
        value={value}
        onChange={onChange}
        placeholder={placeholder || ""}
        autoComplete={autoComplete || "current-password"}
        required
      />
      <button
        type="button"
        className="password-toggle"
        onClick={() => setVisible((v) => !v)}
        aria-label={visible ? "Hide password" : "Show password"}
      >
        {visible ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
    </div>
  );
}

/* =========================================================
   DEMO CREDENTIAL GUIDE (collapsible accordion)
========================= */

function CredentialGuide() {
  const [open, setOpen] = useState(false);
  return (
    <div className="credential-guide">
      <button
        type="button"
        className="credential-guide-toggle"
        onClick={() => setOpen((v) => !v)}
      >
        <Lock size={13} />
        Academic Demo Credentials
        {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
      </button>
      {open && (
        <div className="credential-guide-body">
          <div className="credential-row">
            <span>Administrator</span>
            <code>admin</code>
            <code>Admin@ThreatGuard2026!</code>
          </div>
          <div className="credential-row">
            <span>Security Analyst</span>
            <code>analyst</code>
            <code>Analyst@ThreatGuard2026!</code>
          </div>
          <div className="credential-row">
            <span>Protected Device</span>
            <code>device</code>
            <code>Device@ThreatGuard2026!</code>
          </div>
          <p>
            Authenticated via backend JWT &amp; server-side RBAC. You can also register a new analyst account using the Create Account tab.
          </p>
        </div>
      )}
    </div>
  );
}

/* =========================================================
   SIGN IN TAB — Server-side JWT authentication
========================= */

function SignInForm({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setError("");

    if (!username.trim() || !password) {
      setError("Please enter your username and password.");
      return;
    }

    setLoading(true);
    try {
      const response = await loginUser(username.trim().toLowerCase(), password);
      // Safe user object returned from backend without password hashes
      const user = response.user;
      onLogin(user);
    } catch (err) {
      setError(err?.message || "Invalid username or password. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={submit} noValidate>
      <div className="form-field">
        <label htmlFor="signin-username">
          <User size={14} />
          Username
        </label>
        <input
          id="signin-username"
          type="text"
          value={username}
          onChange={(e) => { setUsername(e.target.value); setError(""); }}
          placeholder="Enter your username"
          autoComplete="username"
          autoFocus
          required
        />
      </div>

      <div className="form-field">
        <label htmlFor="signin-password">
          <Lock size={14} />
          Password
        </label>
        <PasswordInput
          id="signin-password"
          value={password}
          onChange={(e) => { setPassword(e.target.value); setError(""); }}
          placeholder="Enter your password"
          autoComplete="current-password"
        />
      </div>

      {error && (
        <div className="auth-error" role="alert">
          {error}
        </div>
      )}

      <button
        type="submit"
        className="auth-submit"
        disabled={loading}
        aria-busy={loading}
      >
        {loading
          ? <span className="auth-spinner" aria-hidden="true" />
          : <ShieldCheck size={16} />}
        {loading ? "Authenticating via JWT…" : "Sign In to Console"}
      </button>

      <CredentialGuide />
    </form>
  );
}

/* =========================================================
   CREATE ACCOUNT TAB — Server-side analyst registration
========================= */

function CreateAccountForm({ onLogin }) {
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setError("");

    if (!name.trim()) {
      setError("Please enter your full name.");
      return;
    }

    const cleanUsername = username.trim().toLowerCase();
    if (!cleanUsername || cleanUsername.length < 3) {
      setError("Username must be at least 3 characters.");
      return;
    }

    if (!/^[a-z0-9_]+$/.test(cleanUsername)) {
      setError("Username may only contain letters, numbers, and underscores.");
      return;
    }

    const strength = measureStrength(password);
    if (strength.score < 3) {
      setError("Password is too weak. Use at least 8 characters with a number and symbol.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const response = await registerUser(cleanUsername, password, name.trim());
      const user = response.user;
      onLogin(user);
    } catch (err) {
      setError(err?.message || "Registration failed. Please choose another username.");
    } finally {
      setLoading(false);
    }
  };

  const strength = measureStrength(password);

  return (
    <form className="auth-form" onSubmit={submit} noValidate>
      <div className="form-field">
        <label htmlFor="reg-name">
          <User size={14} />
          Full Name
        </label>
        <input
          id="reg-name"
          type="text"
          value={name}
          onChange={(e) => { setName(e.target.value); setError(""); }}
          placeholder="e.g. Alice Johnson"
          autoComplete="name"
          autoFocus
          required
        />
      </div>

      <div className="form-field">
        <label htmlFor="reg-username">
          <User size={14} />
          Username
        </label>
        <input
          id="reg-username"
          type="text"
          value={username}
          onChange={(e) => { setUsername(e.target.value); setError(""); }}
          placeholder="letters, numbers, underscores"
          autoComplete="username"
          required
        />
      </div>

      <div className="form-field">
        <label htmlFor="reg-password">
          <Lock size={14} />
          Password
        </label>
        <PasswordInput
          id="reg-password"
          value={password}
          onChange={(e) => { setPassword(e.target.value); setError(""); }}
          placeholder="Create a strong password"
          autoComplete="new-password"
        />
        <PasswordStrengthBar password={password} />
      </div>

      <div className="form-field">
        <label htmlFor="reg-confirm">
          <Lock size={14} />
          Confirm Password
        </label>
        <PasswordInput
          id="reg-confirm"
          value={confirmPassword}
          onChange={(e) => { setConfirmPassword(e.target.value); setError(""); }}
          placeholder="Repeat your password"
          autoComplete="new-password"
        />
        {confirmPassword && password !== confirmPassword && (
          <span className="field-hint error">Passwords do not match</span>
        )}
        {confirmPassword && password === confirmPassword && password && (
          <span className="field-hint success">Passwords match ✓</span>
        )}
      </div>

      <div className="form-field readonly-role">
        <label>
          <ShieldCheck size={14} />
          Role
        </label>
        <input type="text" value="Security Analyst" readOnly tabIndex={-1} />
        <span className="field-hint">
          New accounts are registered as Security Analysts. Administrator access is controlled separately.
        </span>
      </div>

      {error && (
        <div className="auth-error" role="alert">
          {error}
        </div>
      )}

      <button
        type="submit"
        className="auth-submit"
        disabled={loading || strength.score < 3}
        aria-busy={loading}
      >
        {loading
          ? <span className="auth-spinner" aria-hidden="true" />
          : <UserPlus size={16} />}
        {loading ? "Creating Account via Backend…" : "Create Analyst Account"}
      </button>

      <p className="auth-note">
        Account credentials are encrypted and validated server-side by ThreatGuard.
      </p>
    </form>
  );
}

/* =========================================================
   MAIN LOGIN PAGE
========================= */

function LoginPage({ onLogin }) {
  const [tab, setTab] = useState("signin");

  return (
    <main className="login-page">
      {/* === LEFT BRAND HERO === */}
      <section className="login-hero">
        <div className="login-brand-mark">
          <ShieldCheck size={36} />
        </div>

        <div className="login-brand-wordmark">
          <span className="login-kicker">THREATGUARD SOC</span>
          <h1>Monitor. Detect. Explain. Mitigate.</h1>
          <p>
            AI-powered API abuse detection and response platform for
            enterprise security operations.
          </p>
        </div>

        <ul className="login-capabilities">
          <li>
            <Activity size={15} />
            Real-time API traffic monitoring &amp; anomaly detection
          </li>
          <li>
            <Cpu size={15} />
            XGBoost + Isolation Forest ML pipeline
          </li>
          <li>
            <Database size={15} />
            RAG-augmented Gemini threat intelligence
          </li>
          <li>
            <ShieldCheck size={15} />
            Rule-based detection across 19 attack types
          </li>
        </ul>

        <div className="login-hero-footer">
          <span>Powered by Google Gemini · scikit-learn · FastAPI</span>
        </div>
      </section>

      {/* === RIGHT AUTH CARD === */}
      <section className="login-card">
        <div className="login-card-header">
          <div className="login-card-logo">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h2>Security Console</h2>
            <p>Authenticate to access the SOC dashboard</p>
          </div>
        </div>

        <div className="auth-tabs">
          <button
            type="button"
            className={`auth-tab ${tab === "signin" ? "active" : ""}`}
            onClick={() => setTab("signin")}
          >
            Sign In
          </button>
          <button
            type="button"
            className={`auth-tab ${tab === "register" ? "active" : ""}`}
            onClick={() => setTab("register")}
          >
            Create Account
          </button>
        </div>

        {tab === "signin" ? (
          <SignInForm onLogin={onLogin} />
        ) : (
          <CreateAccountForm onLogin={onLogin} />
        )}
      </section>
    </main>
  );
}

export default LoginPage;

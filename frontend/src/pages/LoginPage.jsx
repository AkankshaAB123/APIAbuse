import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { ROLE_LABELS, ROLES } from "../data/roles";

const demoAccounts = {
  admin: {
    username: "admin",
    name: "admin",
    role: ROLES.ADMIN,
  },
  user: {
    username: "user",
    name: "user",
    role: ROLES.ANALYST,
  },
};

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("demo");

  const submit = (event) => {
    event.preventDefault();
    onLogin(demoAccounts[username] || demoAccounts.user);
  };

  return (
    <main className="login-page">
      <section className="login-hero">
        <div className="login-brand-mark">
          <ShieldCheck size={34} />
        </div>
        <p className="page-kicker">THREATGUARD</p>
        <h1>AI-Powered API Abuse Detection</h1>
        <p>Detect. Analyze. Explain. Mitigate.</p>
      </section>

      <form className="login-panel" onSubmit={submit}>
        <h2>Sign In</h2>
        <p>Demo access for the ThreatGuard security console.</p>

        <label>
          Username
          <input
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value.trim().toLowerCase())}
            required
          />
        </label>

        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>

        <button className="primary-action" type="submit">
          SIGN IN
        </button>

        <div className="demo-account-grid">
          {Object.values(demoAccounts).map((account) => (
            <button
              className="secondary-action"
              key={account.username}
              type="button"
              onClick={() => onLogin(account)}
            >
              {account.username} - {ROLE_LABELS[account.role]}
            </button>
          ))}
        </div>

        <button
          className="secondary-action"
          type="button"
          onClick={() =>
            onLogin(demoAccounts.user)
          }
        >
          TRY SECURITY DEMO
        </button>
      </form>
    </main>
  );
}

export default LoginPage;

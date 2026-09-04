import { useState } from "react";
import { ShieldCheck } from "lucide-react";

function LoginPage({ onLogin }) {
  const [email, setEmail] = useState("admin@threatguard.local");
  const [password, setPassword] = useState("demo");

  const submit = (event) => {
    event.preventDefault();
    onLogin({
      name: email.split("@")[0] || "Admin",
      email,
    });
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
          Email
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
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

        <button
          className="secondary-action"
          type="button"
          onClick={() =>
            onLogin({
              name: "Demo Analyst",
              email: "demo@threatguard.local",
            })
          }
        >
          TRY SECURITY DEMO
        </button>
      </form>
    </main>
  );
}

export default LoginPage;

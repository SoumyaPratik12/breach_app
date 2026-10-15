import { useEffect, useState } from "react";
import "./App.css";

const TOKEN_KEY = "dfsa_access_token";
const API_BASE = "/api";

async function apiRequest(path, options = {}, token = null) {
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const detail = data.detail;
    const message =
      typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? detail.map((item) => item.msg || "Invalid input").join(", ")
          : `Request failed with status ${response.status}`;


    throw new Error(message);
  }

  return data;
}

function App() {
  const [mode, setMode] = useState("register");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(
    () => sessionStorage.getItem(TOKEN_KEY)
  );

  const [identifiers, setIdentifiers] = useState([]);
  const [identifierType, setIdentifierType] = useState("email");
  const [identifierValue, setIdentifierValue] = useState("");
  const [selectedIdentifierId, setSelectedIdentifierId] = useState(null);
  const [otp, setOtp] = useState("");
  const [devOtp, setDevOtp] = useState("");
  const [otpExpiresAt, setOtpExpiresAt] = useState("");
  const [scan, setScan] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);

  const [loading, setLoading] = useState(false);
  const [checkingSession, setCheckingSession] = useState(true);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function restoreSession() {
      if (!token) {
        setUser(null);
        setIdentifiers([]);
        setCheckingSession(false);
        return;
      }

      try {
        const currentUser = await apiRequest("/auth/me", {}, token);
        if (!cancelled) setUser(currentUser);
      } catch {
        sessionStorage.removeItem(TOKEN_KEY);

        if (!cancelled) {
          setToken(null);
          setUser(null);
          setIdentifiers([]);
        }
      } finally {
        if (!cancelled) setCheckingSession(false);
      }
    }

    restoreSession();

    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    let cancelled = false;

    async function loadIdentifiers() {
      if (!user || !token) {
        setIdentifiers([]);
        return;
      }

      try {
        const data = await apiRequest("/identifiers", {}, token);
        if (!cancelled) setIdentifiers(data);
      } catch (requestError) {
        if (!cancelled) {
          setError(requestError.message || "Could not load identifiers.");
        }
      }
    }

    loadIdentifiers();

    return () => {
      cancelled = true;
    };
  }, [user, token]);

  function clearFeedback() {
    setMessage("");
    setError("");
  }

  async function handleSubmit(event) {
    event.preventDefault();
    clearFeedback();
    setLoading(true);

    try {
      const endpoint =
        mode === "register" ? "/auth/register" : "/auth/login";

      const result = await apiRequest(endpoint, {
        method: "POST",
        body: JSON.stringify({
          email: email.trim(),
          password,
        }),
      });

      sessionStorage.setItem(TOKEN_KEY, result.access_token);
      setToken(result.access_token);
      setPassword("");

      const currentUser = await apiRequest(
        "/auth/me",
        {},
        result.access_token
      );

      setUser(currentUser);
      setMessage(
        mode === "register"
          ? "Account created successfully."
          : "You are now logged in."
      );
    } catch (requestError) {
      setError(requestError.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  async function handleAddIdentifier(event) {
    event.preventDefault();
    clearFeedback();
    setLoading(true);

    try {
      await apiRequest(
        "/identifiers",
        {
          method: "POST",
          body: JSON.stringify({
            type: identifierType,
            value: identifierValue.trim(),
          }),
        },
        token
      );

      setIdentifierValue("");
      const data = await apiRequest("/identifiers", {}, token);
      setIdentifiers(data);
      setMessage("Identifier added. Verify ownership before scanning.");
    } catch (requestError) {
      setError(requestError.message || "Could not add identifier.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRequestOtp(identifierId) {
    clearFeedback();
    setLoading(true);
    setSelectedIdentifierId(identifierId);
    setOtp("");
    setDevOtp("");
    setOtpExpiresAt("");

    try {
      const result = await apiRequest(
        `/identifiers/${identifierId}/otp`,
        { method: "POST" },
        token
      );

      setDevOtp(result.dev_otp || "");
      setOtpExpiresAt(result.expires_at || "");
      setMessage(
        result.dev_otp
          ? "Development OTP generated. Use it only for local testing."
          : "Verification code requested. Check your verified delivery channel."
      );
    } catch (requestError) {
      setSelectedIdentifierId(null);
      setError(requestError.message || "Could not request an OTP.");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyOtp(event) {
    event.preventDefault();
    clearFeedback();
    setLoading(true);

    try {
      const result = await apiRequest(
        `/identifiers/${selectedIdentifierId}/verify`,
        {
          method: "POST",
          body: JSON.stringify({ otp }),
        },
        token
      );

      const data = await apiRequest("/identifiers", {}, token);
      setIdentifiers(data);
      setOtp("");
      setDevOtp("");
      setSelectedIdentifierId(null);
      setOtpExpiresAt("");
      setMessage(result.message || "Identifier verified successfully.");
    } catch (requestError) {
      setError(requestError.message || "OTP verification failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleStartScan(identifierId) {
    clearFeedback();
    setScan(null);
    setScanLoading(true);

    try {
      const result = await apiRequest(
        `/identifiers/${identifierId}/scans`,
        { method: "POST" },
        token
      );

      setScan(result);
      setMessage("Scan finished. Review the simulated findings below.");
    } catch (requestError) {
      setError(requestError.message || "Could not start the scan.");
    } finally {
      setScanLoading(false);
    }
  }

  async function handleRefreshScan() {
    if (!scan?.id) return;

    clearFeedback();
    setScanLoading(true);

    try {
      const result = await apiRequest(`/scans/${scan.id}`, {}, token);
      setScan(result);
      setMessage("Scan results refreshed.");
    } catch (requestError) {
      setError(requestError.message || "Could not refresh scan results.");
    } finally {
      setScanLoading(false);
    }
  }

  function handleLogout() {
    sessionStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
    setIdentifiers([]);
    setScan(null);
    setEmail("");
    setPassword("");
    setIdentifierValue("");
    setOtp("");
    setDevOtp("");
    setSelectedIdentifierId(null);
    setMode("login");
    setMessage("You have been logged out.");
    setError("");
  }

  function switchMode(nextMode) {
    setMode(nextMode);
    clearFeedback();
    setPassword("");
  }

  if (checkingSession) {
    return (
      <main className="app loading-screen" aria-live="polite">
        Checking your session…
      </main>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <a className="brand" href="#home" aria-label="Digital Footprint home">
          <span className="brand-mark" aria-hidden="true">D</span>
          <span>Digital Footprint</span>
        </a>
        <span className="header-note">Privacy-first assessment</span>
      </header>

      <main
        className={user ? "dashboard-layout" : "hero"}
        id="home"
      >
        <section className="hero-copy">
          <p className="eyebrow">YOUR PRIVACY, YOUR CONTROL</p>
          <h1>
            Understand what is exposed.
            <br />
            Take control of what comes next.
          </h1>
          <p className="description">
            Manage your own identifiers, verify ownership, and prepare for
            a privacy exposure assessment.
          </p>
          <ul className="benefit-list">
            <li>Account-based access to your assessment</li>
            <li>Ownership verification before scanning</li>
            <li>Masked identifiers in your dashboard</li>
          </ul>
          <p className="privacy-note">
            Only add email addresses or phone numbers that you own or are
            explicitly authorized to verify.
          </p>
        </section>

        <section
          className={user ? "dashboard-card" : "auth-card"}
          aria-labelledby="auth-heading"
        >
          {!user ? (
            <>
              <div className="auth-heading">
                <p className="eyebrow">
                  {mode === "register" ? "GET STARTED" : "WELCOME BACK"}
                </p>
                <h2 id="auth-heading">
                  {mode === "register" ? "Create your account" : "Log in"}
                </h2>
                <p className="muted">
                  {mode === "register"
                    ? "Use your own email address to get started."
                    : "Sign in to continue your assessment."}
                </p>
              </div>

              <div className="auth-tabs" aria-label="Authentication mode">
                <button
                  type="button"
                  className={mode === "register" ? "tab active" : "tab"}
                  aria-pressed={mode === "register"}
                  onClick={() => switchMode("register")}
                >
                  Create account
                </button>
                <button
                  type="button"
                  className={mode === "login" ? "tab active" : "tab"}
                  aria-pressed={mode === "login"}
                  onClick={() => switchMode("login")}
                >
                  Log in
                </button>
              </div>

              <form onSubmit={handleSubmit}>
                <label htmlFor="email">Email address</label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                />

                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  autoComplete={
                    mode === "register" ? "new-password" : "current-password"
                  }
                  minLength={mode === "register" ? 8 : undefined}
                  maxLength={128}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                />

                <button className="primary-button" type="submit" disabled={loading}>
                  {loading
                    ? "Please wait…"
                    : mode === "register"
                      ? "Create account"
                      : "Log in"}
                </button>
              </form>
            </>
          ) : (
            <div className="account-panel">
              <div className="success-icon" aria-hidden="true">✓</div>
              <p className="eyebrow">ACCOUNT CONNECTED</p>
              <h2 id="auth-heading">Privacy dashboard</h2>
              <p className="muted">Signed in as {user.email}</p>

              <div className="dashboard-overview">
                <article className="overview-card">
                  <span>Saved identifiers</span>
                  <strong>{identifiers.length}</strong>
                  <small>In your identifier vault</small>
                </article>

                <article className="overview-card">
                  <span>Ownership verified</span>
                  <strong>
                    {
                      identifiers.filter(
                        (identifier) =>
                          String(identifier.verification_status).toLowerCase() ===
                          "verified"
                      ).length
                    }
                    <span className="overview-total"> / {identifiers.length}</span>
                  </strong>
                  <small>Verified identifiers</small>
                </article>

                <article className="overview-card">
                  <span>Latest scan risk</span>
                  <strong>
                    {scan?.status === "completed" && scan.risk_score != null
                      ? `${scan.risk_score}/100`
                      : "—"}
                  </strong>
                  <small>
                    {scan?.status === "completed"
                      ? `Risk level: ${scan.risk_level}`
                      : "Complete a scan to see the score"}
                  </small>
                </article>
              </div>

              <div className="dashboard-grid">
                <section className="dashboard-panel">
                  <div className="dashboard-panel-heading">
                    <p className="eyebrow">IDENTIFIER VAULT</p>
                    <h3>Add an identifier</h3>
                    <p className="muted">
                      Add only identifiers you own or are authorized to verify.
                    </p>
                  </div>
              <form className="identifier-form" onSubmit={handleAddIdentifier}>
                <label htmlFor="identifier-type">Identifier type</label>
                <select
                  id="identifier-type"
                  value={identifierType}
                  onChange={(event) => setIdentifierType(event.target.value)}
                >
                  <option value="email">Email address</option>
                  <option value="phone">Phone number</option>
                </select>

                <label htmlFor="identifier-value">
                  {identifierType === "email" ? "Email address you own" : "Phone number you own"}
                </label>
                <input
                  id="identifier-value"
                  type={identifierType === "email" ? "email" : "tel"}
                  autoComplete="off"
                  placeholder={
                    identifierType === "email"
                      ? "you@example.com"
                      : "+14155550123"
                  }
                  value={identifierValue}
                  onChange={(event) => setIdentifierValue(event.target.value)}
                  required
                />

                <button className="primary-button" type="submit" disabled={loading}>
                  {loading ? "Please wait…" : "Add identifier"}
                </button>
              </form>

                </section>

                <section className="dashboard-panel">
              <div className="identifier-list">
                <h3>Your identifiers</h3>
                {identifiers.length === 0 ? (
                  <p className="muted">No identifiers added yet.</p>
                ) : (
                  identifiers.map((identifier) => {
                    const verified =
                      String(identifier.verification_status).toLowerCase() ===
                      "verified";

                    return (
                      <article className="identifier-item" key={identifier.id}>
                        <div className="identifier-details">
                          <strong>{identifier.display_value}</strong>
                          <span>
                            {identifier.type} · {identifier.verification_status}
                          </span>
                        </div>
                        {verified ? (
                          <div className="identifier-actions">
                            <span className="verified-label">Verified</span>
                            <button
                              className="secondary-button"
                              type="button"
                              disabled={scanLoading || loading}
                              onClick={() => handleStartScan(identifier.id)}
                            >
                              {scanLoading ? "Scanning…" : "Start scan"}
                            </button>
                          </div>
                        ) : (
                          <button
                            className="secondary-button"
                            type="button"
                            disabled={loading}
                            onClick={() => handleRequestOtp(identifier.id)}
                          >
                            Verify
                          </button>
                        )}
                      </article>
                    );
                  })
                )}
              </div>
                </section>
              </div>

              {scan && (
                <section className="scan-results" aria-labelledby="scan-heading">
                  <div className="scan-results-header">
                    <div>
                      <p className="eyebrow">EXPOSURE ASSESSMENT</p>
                      <h3 id="scan-heading">Scan results</h3>
                    </div>
                    <span className="scan-status">{scan.status}</span>
                  </div>

                  <div className="simulation-notice" role="note">
                    <strong>
                      Simulated results — not verified real-world exposure
                    </strong>
                    <p>
                      These findings come from a mock provider. They do not
                      confirm that your information appeared in a real breach
                      or public source.
                    </p>
                  </div>

                  <p className="muted">
                    Scan ID: <code>{scan.id}</code>
                  </p>

                  {scan.status === "completed" && (
                    <section className="risk-summary" aria-label="Risk summary">
                      <div className="risk-score">
                        <span className="muted">Risk score</span>
                        <strong>{scan.risk_score ?? "—"} / 100</strong>
                        <span className={`risk-level risk-${scan.risk_level}`}>
                          {scan.risk_level}
                        </span>
                      </div>

                      <div className="severity-summary">
                        {["high", "medium", "low"].map((severity) => (
                          <div className="severity-count" key={severity}>
                            <span>{severity}</span>
                            <strong>
                              {scan.severity_counts?.[severity] ?? 0}
                            </strong>
                          </div>
                        ))}
                      </div>
                    </section>
                  )}

                  {scan.error_code && (
                    <p className="feedback error">
                      The scan could not complete ({scan.error_code}).
                    </p>
                  )}

                  {scan.findings?.length > 0 ? (
                    <div className="finding-list">
                      {scan.findings.map((finding, index) => (
                        <article
                          className="finding-card"
                          key={`${finding.category}-${finding.source}-${index}`}
                        >
                          <div className="finding-heading">
                            <strong>
                              {finding.category.replaceAll("_", " ")}
                            </strong>
                            <span
                              className={`severity severity-${finding.severity}`}
                            >
                              {finding.severity}
                            </span>
                          </div>
                          <p>{finding.description}</p>
                          <span className="finding-source">
                            Source: {finding.source}
                          </span>
                          <span className="finding-source">
                            Simulated: {String(finding.simulated)} ·
                            Independently verified: {String(finding.verified)}
                          </span>
                        </article>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">
                      {scan.status === "completed"
                        ? "No findings were returned by the simulated provider."
                        : "No findings are available for this scan status."}
                    </p>
                  )}

                  {scan.status === "completed" &&
                    scan.recommendations?.length > 0 && (
                      <section
                        className="recommendations-section"
                        aria-labelledby="recommendations-heading"
                      >
                        <div>
                          <p className="eyebrow">NEXT STEPS</p>
                          <h4 id="recommendations-heading">
                            Cleanup recommendations
                          </h4>
                          <p className="muted">
                            These are advisory actions, not automated fixes.
                            Verify a finding independently before treating it
                            as a real exposure.
                          </p>
                        </div>

                        <div className="recommendation-list">
                          {scan.recommendations.map((recommendation, index) => (
                            <article
                              className="recommendation-card"
                              key={`${recommendation.category}-${index}`}
                            >
                              <div className="finding-heading">
                                <strong>{recommendation.title}</strong>
                                <span
                                  className={`severity severity-${recommendation.priority}`}
                                >
                                  {recommendation.priority} priority
                                </span>
                              </div>

                              <ol>
                                {recommendation.steps.map((step, stepIndex) => (
                                  <li key={`${index}-${stepIndex}`}>{step}</li>
                                ))}
                              </ol>

                              <p className="finding-source">
                                {recommendation.advisory_only
                                  ? "Advisory only"
                                  : "Recommendation"}
                                {" · "}
                                Simulated: {String(recommendation.simulated)}
                                {" · "}
                                Verified: {String(recommendation.verified)}
                              </p>
                            </article>
                          ))}
                        </div>
                      </section>
                    )}

                  <button
                    className="secondary-button"
                    type="button"
                    disabled={scanLoading}
                    onClick={handleRefreshScan}
                  >
                    {scanLoading ? "Refreshing…" : "Refresh scan results"}
                  </button>
                </section>
              )}

              {selectedIdentifierId && (
                <form className="otp-form" onSubmit={handleVerifyOtp}>
                  <h3>Verify ownership</h3>
                  <p className="muted">
                    Enter the six-digit code for the selected identifier.
                  </p>

                  {devOtp && (
                    <div className="dev-otp-notice" role="status">
                      <strong>Local development OTP: {devOtp}</strong>
                      <p>
                        This code is exposed only by the backend's development
                        configuration. Never enable this in production.
                      </p>
                    </div>
                  )}

                  {otpExpiresAt && (
                    <p className="muted">
                      Expires: {new Date(otpExpiresAt).toLocaleString()}
                    </p>
                  )}

                  <label htmlFor="otp">Six-digit OTP</label>
                  <input
                    id="otp"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    minLength={6}
                    maxLength={6}
                    value={otp}
                    onChange={(event) =>
                      setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))
                    }
                    required
                  />

                  <button className="primary-button" type="submit" disabled={loading}>
                    {loading ? "Verifying…" : "Verify ownership"}
                  </button>
                  <button
                    className="text-button"
                    type="button"
                    onClick={() => {
                      setSelectedIdentifierId(null);
                      setOtp("");
                      setDevOtp("");
                      setOtpExpiresAt("");
                    }}
                  >
                    Cancel verification
                  </button>
                </form>
              )}

              <button className="logout-button" type="button" onClick={handleLogout}>
                Log out
              </button>
            </div>
          )}

          {error && <p className="feedback error" role="alert">{error}</p>}
          {message && <p className="feedback success" role="status">{message}</p>}
        </section>
      </main>

      <footer className="footer">
        Digital Footprint Exposure Scanner · Development MVP
      </footer>
    </div>
  );
}

export default App;

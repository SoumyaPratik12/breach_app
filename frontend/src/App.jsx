import "./App.css";

function App() {
  return (
    <div className="app">
      <header className="header">
        <div className="brand">Digital Footprint</div>

        <nav aria-label="Main navigation">
          <a href="#dashboard">Dashboard</a>
          <a href="#exposure">Exposure</a>
          <a href="#cleanup">Cleanup</a>
        </nav>
      </header>

      <main className="hero">
        <section>
          <p className="eyebrow">PRIVACY EXPOSURE ASSESSMENT</p>

          <h1>
            Understand what is exposed.
            <br />
            Take control of what comes next.
          </h1>

          <p className="description">
            Verify your identity, discover known exposure, and turn findings
            into a practical cleanup plan.
          </p>

          <button type="button">Start your assessment</button>
        </section>

        <section className="status-card" aria-label="Digital exposure status">
          <span>YOUR DIGITAL EXPOSURE</span>
          <strong>Not scanned</strong>
          <p>Verify your identity to begin.</p>
        </section>
      </main>
    </div>
  )
}

export default App;

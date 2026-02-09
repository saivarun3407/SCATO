// ─── Built-in Dashboard ───
// Returns self-contained HTML for the SCATO web UI
// No build step, no external dependencies — just one HTML string

export function getDashboardHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCATO — Software Composition Analysis</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0f1117; --surface: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8b949e; --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --orange: #d29922; --yellow: #e3b341; --blue: #58a6ff; --purple: #bc8cff;
    --radius: 8px; --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  }
  body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Layout */
  .app { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .header { display: flex; align-items: center; justify-content: space-between; padding: 16px 0 24px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
  .header h1 { font-size: 1.5rem; font-weight: 700; }
  .header h1 span { color: var(--accent); }
  .header .version { color: var(--muted); font-size: 0.85rem; font-weight: 400; }

  /* Tabs */
  .tabs { display: flex; gap: 4px; margin-bottom: 24px; }
  .tab { padding: 8px 16px; border-radius: var(--radius); cursor: pointer; font-size: 0.9rem; color: var(--muted); background: transparent; border: 1px solid transparent; transition: all 0.2s; }
  .tab:hover { color: var(--text); background: var(--surface); }
  .tab.active { color: var(--text); background: var(--surface); border-color: var(--border); }

  /* Cards */
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; margin-bottom: 16px; }
  .card h2 { font-size: 1.1rem; margin-bottom: 12px; }
  .card h3 { font-size: 0.95rem; color: var(--muted); margin-bottom: 8px; }

  /* Scan Form */
  .scan-form { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
  .scan-form .field { flex: 1; min-width: 300px; }
  .scan-form label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 6px; }
  .scan-form input { width: 100%; padding: 10px 14px; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); color: var(--text); font-size: 0.95rem; }
  .scan-form input:focus { outline: none; border-color: var(--accent); }
  .btn { padding: 10px 20px; border-radius: var(--radius); border: none; font-size: 0.9rem; font-weight: 600; cursor: pointer; transition: all 0.2s; }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { opacity: 0.9; }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-secondary { background: var(--surface); color: var(--text); border: 1px solid var(--border); }
  .btn-secondary:hover { border-color: var(--muted); }

  /* Options row */
  .options-row { display: flex; gap: 16px; margin-top: 12px; flex-wrap: wrap; align-items: center; }
  .options-row label { display: flex; align-items: center; gap: 6px; font-size: 0.85rem; color: var(--muted); cursor: pointer; }
  .options-row input[type="checkbox"] { accent-color: var(--accent); }

  /* Stats Grid */
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; text-align: center; }
  .stat .value { font-size: 1.8rem; font-weight: 700; }
  .stat .label { font-size: 0.8rem; color: var(--muted); margin-top: 4px; }
  .stat.critical .value { color: var(--red); }
  .stat.high .value { color: var(--orange); }
  .stat.medium .value { color: var(--yellow); }
  .stat.low .value { color: var(--blue); }
  .stat.ok .value { color: var(--green); }

  /* Severity Badges */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: rgba(248,81,73,0.2); color: var(--red); }
  .badge-high { background: rgba(210,153,34,0.2); color: var(--orange); }
  .badge-medium { background: rgba(227,179,65,0.2); color: var(--yellow); }
  .badge-low { background: rgba(88,166,255,0.2); color: var(--blue); }
  .badge-unknown { background: rgba(139,148,158,0.2); color: var(--muted); }
  .badge-kev { background: rgba(248,81,73,0.3); color: var(--red); }

  /* Results Table */
  .results-list { display: flex; flex-direction: column; gap: 8px; }
  .result-item { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; }
  .result-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
  .result-pkg { font-weight: 600; }
  .result-eco { color: var(--muted); font-size: 0.85rem; }
  .result-badges { display: flex; gap: 6px; flex-wrap: wrap; }
  .vuln-list { margin-top: 10px; display: flex; flex-direction: column; gap: 6px; }
  .vuln-item { padding: 8px 12px; background: var(--surface); border-radius: 6px; font-size: 0.9rem; cursor: pointer; transition: background 0.15s; border: 1px solid transparent; }
  .vuln-item:hover { background: var(--border); }
  .vuln-item-clickable { cursor: pointer; }
  .vuln-id { font-weight: 600; margin-right: 8px; }
  .vuln-summary { color: var(--muted); }
  .vuln-fix { color: var(--green); font-size: 0.85rem; margin-top: 4px; }
  .vuln-meta { color: var(--muted); font-size: 0.8rem; margin-top: 2px; }

  /* Dependency tree / grouped view */
  .dep-section { margin-bottom: 20px; }
  .dep-section-title { font-size: 0.9rem; font-weight: 600; color: var(--muted); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.05em; }
  .dep-group { margin-bottom: 12px; }
  .dep-node { padding: 10px 14px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface); }
  .dep-node.has-vuln { border-left: 3px solid var(--orange); }
  .dep-node.direct { background: var(--bg); }
  .dep-node .dep-name { font-weight: 600; }
  .dep-node .dep-meta { font-size: 0.85rem; color: var(--muted); margin-top: 2px; }
  .dep-children { margin-top: 8px; margin-left: 16px; padding-left: 12px; border-left: 2px solid var(--border); display: flex; flex-direction: column; gap: 6px; }
  .dep-child { font-size: 0.9rem; }
  .dep-child .brought-in { font-size: 0.8rem; color: var(--muted); }
  .dep-node-clickable, .dep-child-clickable { cursor: pointer; }
  .dep-tree-label { cursor: pointer; }

  /* Dependency tree view — terminal/file-explorer style */
  .dep-tree-eco { margin-bottom: 24px; }
  .dep-tree-eco-title { font-size: 0.85rem; font-weight: 600; color: var(--muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .dep-tree-root { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.88rem; line-height: 1.7; white-space: pre; color: var(--text); }
  .dep-tree-line { display: block; }
  .dep-tree-line:hover { background: rgba(88,166,255,0.06); border-radius: 3px; }
  .dep-tree-connector { color: var(--border); user-select: none; }
  .dep-tree-pkg { color: var(--accent); cursor: pointer; }
  .dep-tree-pkg:hover { text-decoration: underline; }
  .dep-tree-ver { color: var(--muted); }
  .dep-tree-pkg.has-vuln { color: var(--orange); }
  .dep-tree-badge { font-size: 0.72rem; padding: 1px 5px; border-radius: 8px; background: var(--orange); color: #fff; margin-left: 4px; font-family: var(--font); }
  .dep-tree-toggle-btn { color: var(--muted); cursor: pointer; font-size: 0.7rem; margin-left: 4px; }
  .dep-tree-toggle-btn:hover { color: var(--accent); }

  /* Advisory count summary */
  .advisory-total { font-size: 0.85rem; font-weight: 600; color: var(--text); margin-right: 6px; }

  /* Vulnerability detail modal */
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .modal { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); max-width: 640px; width: 100%; max-height: 90vh; overflow: hidden; display: flex; flex-direction: column; }
  .modal-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
  .modal-header h2 { font-size: 1.1rem; margin: 0; }
  .modal-close { background: none; border: none; color: var(--muted); cursor: pointer; font-size: 1.5rem; line-height: 1; padding: 0 4px; }
  .modal-close:hover { color: var(--text); }
  .modal-body { padding: 20px; overflow-y: auto; flex: 1; }
  .dep-modal-tree { margin-top: 8px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.88rem; line-height: 1.7; white-space: pre; }
  .dep-modal-tree .mtree-connector { color: var(--border); }
  .dep-modal-tree .mtree-name { color: var(--accent); }
  .dep-modal-tree .mtree-ver { color: var(--muted); }
  .vuln-detail-section { margin-bottom: 16px; }
  .vuln-detail-section h4 { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
  .vuln-detail-section p, .vuln-detail-section div { font-size: 0.9rem; line-height: 1.5; }
  .vuln-detail-links { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  .vuln-detail-links a { display: inline-block; padding: 6px 12px; background: var(--bg); border-radius: 6px; font-size: 0.85rem; }
  .vuln-detail-links a:hover { background: var(--border); }

  /* History */
  .history-table { width: 100%; border-collapse: collapse; }
  .history-table th { text-align: left; font-size: 0.8rem; color: var(--muted); padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .history-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  .history-table tr:hover td { background: var(--bg); }
  .history-table .risk-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }

  /* Loading & Empty States */
  .loading { text-align: center; padding: 60px 20px; color: var(--muted); }
  .spinner { display: inline-block; width: 32px; height: 32px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 12px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .empty { text-align: center; padding: 60px 20px; color: var(--muted); }
  .empty p { margin-top: 8px; }

  /* Export bar */
  .export-bar { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }

  .view-bar { display: flex; gap: 8px; align-items: center; margin-top: 12px; flex-wrap: wrap; }
  .view-bar-label { font-size: 0.9rem; color: var(--muted); font-weight: 500; }
  .result-view-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .result-view-panel { margin-top: 16px; }

  /* List toolbar: search, sort, filter */
  .list-toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
  .list-toolbar .search-wrap { flex: 1; min-width: 180px; }
  .list-toolbar input[type="text"] { width: 100%; padding: 8px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); color: var(--text); font-size: 0.9rem; }
  .list-toolbar input[type="text"]:focus { outline: none; border-color: var(--accent); }
  .list-toolbar input[type="text"]::placeholder { color: var(--muted); }
  .list-toolbar label { font-size: 0.85rem; color: var(--muted); margin-right: 4px; }
  .list-toolbar select { padding: 8px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); color: var(--text); font-size: 0.9rem; cursor: pointer; }
  .list-toolbar select:focus { outline: none; border-color: var(--accent); }
  .list-toolbar { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 16px; }

  /* Risk meter */
  .risk-meter { display: flex; align-items: center; gap: 12px; margin: 12px 0; }
  .risk-bar-bg { flex: 1; height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; }
  .risk-bar { height: 100%; border-radius: 4px; transition: width 0.5s ease; }
  .risk-label { font-size: 1.2rem; font-weight: 700; min-width: 60px; text-align: right; }

  /* Prioritized Remediation Plan */
  .remediation-header { margin-bottom: 4px; }
  .remediation-header h3 { margin: 0; }
  .remediation-summary-box { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 16px; margin-bottom: 14px; }
  .remediation-summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-top: 8px; }
  .remediation-summary-stat { text-align: center; }
  .remediation-summary-stat .val { font-size: 1.3rem; font-weight: 800; }
  .remediation-summary-stat .lbl { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
  .remediation-action { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; margin-bottom: 10px; transition: border-color 0.2s; }
  .remediation-action:hover { border-color: var(--accent); }
  .remediation-action-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
  .remediation-action-left { flex: 1; min-width: 200px; }
  .remediation-action-pkg { font-weight: 700; font-size: 1rem; }
  .remediation-action-upgrade { color: var(--green); font-size: 0.9rem; margin-top: 2px; }
  .remediation-action-right { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  .remediation-metric { display: inline-flex; flex-direction: column; align-items: center; padding: 4px 12px; border-radius: 8px; font-size: 0.78rem; min-width: 64px; }
  .remediation-metric .m-val { font-weight: 800; font-size: 1rem; }
  .remediation-metric .m-lbl { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.3px; opacity: 0.8; }
  .metric-risk { background: rgba(248,81,73,0.15); color: var(--red); }
  .metric-roi { background: rgba(63,185,80,0.15); color: var(--green); }
  .metric-epss { background: rgba(255,166,87,0.15); color: var(--orange); }
  .metric-cvss { background: rgba(136,192,208,0.15); color: var(--accent); }
  .remediation-analysis { margin-top: 12px; font-size: 0.85rem; line-height: 1.65; color: var(--text); border-left: 3px solid var(--border); padding-left: 12px; }
  .remediation-analysis dt { font-weight: 700; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 8px; }
  .remediation-analysis dt:first-child { margin-top: 0; }
  .remediation-analysis dd { margin: 2px 0 0 0; }
  .remediation-badges { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }
  .remediation-rank { width: 28px; height: 28px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-weight: 800; font-size: 0.85rem; background: var(--accent); color: var(--bg-dark); flex-shrink: 0; }

  /* Hidden */
  .hidden { display: none !important; }

  /* Responsive */
  @media (max-width: 640px) {
    .scan-form { flex-direction: column; }
    .scan-form .field { min-width: unset; }
    .stats { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="app" id="app">
  <!-- Header -->
  <div class="header">
    <h1><span>SCATO</span> <span class="version">v3.0.0</span></h1>
    <div style="display:flex;gap:8px;align-items:center;">
      <span style="color:var(--green);font-size:0.85rem;" id="statusDot">&#9679; Connected</span>
    </div>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <div class="tab active" data-tab="scan">Scan</div>
    <div class="tab" data-tab="history">History</div>
  </div>

  <!-- Scan Tab -->
  <div id="tab-scan">
    <div class="card">
      <h2>Run a Scan</h2>
      <div class="scan-form">
        <div class="field">
          <label for="targetInput">Target Directory</label>
          <input id="targetInput" type="text" placeholder="Absolute path to project, or . (server&#39;s current directory)" value="." title="Path is resolved on the server. Use . to scan where the server was started." />
        </div>
        <button type="button" class="btn btn-primary" id="scanBtn" onclick="runScan()">Scan</button>
      </div>
      <div class="options-row">
        <label><input type="checkbox" id="optSkipLicenses"> Skip licenses</label>
        <label><input type="checkbox" id="optSkipDev"> Skip dev deps</label>
      </div>
    </div>

    <!-- Loading state -->
    <div id="scanLoading" class="loading hidden">
      <div class="spinner"></div>
      <div>Scanning dependencies and querying vulnerability databases...</div>
    </div>

    <!-- Results -->
    <div id="scanResults" class="hidden">
      <!-- Summary stats -->
      <div class="stats" id="statsGrid"></div>
      <p id="noDepsHint" class="hidden" style="margin-top:8px;color:var(--muted);font-size:0.9rem;"></p>

      <!-- Risk Score -->
      <div class="card" id="riskCard">
        <h3>Risk Assessment</h3>
        <div class="risk-meter">
          <div class="risk-bar-bg"><div class="risk-bar" id="riskBar"></div></div>
          <div class="risk-label" id="riskLabel">0</div>
        </div>
      </div>

      <!-- Prioritized Remediation Plan -->
      <div class="card hidden" id="remediationCard">
        <div class="remediation-header">
          <h3>Prioritized Remediation Plan</h3>
        </div>
        <div class="remediation-summary-box" id="remediationSummaryBox"></div>
        <div id="remediationActions"></div>
      </div>

      <!-- Export buttons -->
      <div class="export-bar">
        <button class="btn btn-secondary" onclick="exportJSON()">Export JSON</button>
        <button class="btn btn-secondary" onclick="exportSBOM()">Export SBOM (CycloneDX)</button>
      </div>
      <!-- View results: Vulnerabilities (default) or Dependencies -->
      <div class="view-bar">
        <span class="view-bar-label">View:</span>
        <button type="button" class="btn btn-secondary result-view-btn active" id="btnViewVulns" onclick="showResultView('vulns')">Vulnerabilities</button>
        <button type="button" class="btn btn-secondary result-view-btn" id="btnViewDeps" onclick="showResultView('deps')">Dependencies</button>
      </div>

      <!-- Vulnerability results (default: only this is shown) -->
      <div class="card result-view-panel" id="vulnPanel">
        <h2 id="vulnTitle">Vulnerabilities</h2>
        <div class="list-toolbar" id="vulnToolbar" style="margin-top:12px;">
          <div class="search-wrap" style="min-width:200px;">
            <input type="text" id="vulnSearch" placeholder="Search library name..." oninput="applyVulnFilters()" title="Type to filter by library name" />
          </div>
          <label for="vulnSort">Sort:</label>
          <select id="vulnSort" onchange="applyVulnFilters()">
            <option value="severity">Severity (worst first)</option>
            <option value="kev">KEV first (exploited)</option>
            <option value="epss">EPSS (most likely exploited)</option>
            <option value="advisories">Advisories (most first)</option>
            <option value="name">Library name A–Z</option>
          </select>
          <label for="vulnFilter">Filter:</label>
          <select id="vulnFilter" onchange="applyVulnFilters()">
            <option value="">All severities</option>
            <option value="KEV">KEV only (known exploited)</option>
            <option value="CRITICAL">Critical only</option>
            <option value="HIGH">High and above</option>
            <option value="MEDIUM">Medium and above</option>
            <option value="LOW">Low and above</option>
          </select>
        </div>
        <div id="vulnFilterStatus" style="display:none;padding:8px 12px;margin-bottom:8px;background:rgba(136,192,208,0.1);border-radius:6px;font-size:0.85rem;color:var(--accent);"></div>
        <div class="results-list" id="resultsList"></div>
      </div>

      <!-- Dependencies (hidden until "Dependencies" is clicked) -->
      <div class="card result-view-panel hidden" id="depPanel">
        <h2>Dependencies</h2>
        <div class="list-toolbar" id="depToolbar" style="margin-top:12px;">
          <div class="search-wrap" style="min-width:200px;">
            <input type="text" id="depSearch" placeholder="Search library name..." oninput="applyDepFilters()" title="Type to filter by library name" />
          </div>
          <label for="depSort">Sort:</label>
          <select id="depSort" onchange="applyDepFilters()">
            <option value="advisories">Advisories (most first)</option>
            <option value="kev">KEV first (exploited)</option>
            <option value="severity">Severity (worst first)</option>
            <option value="name">Library name A–Z</option>
          </select>
          <label for="depFilter">Filter:</label>
          <select id="depFilter" onchange="applyDepFilters()">
            <option value="">All</option>
            <option value="KEV">KEV only (known exploited)</option>
            <option value="hasVuln">With advisories only</option>
            <option value="CRITICAL">Critical only</option>
            <option value="HIGH">High+</option>
            <option value="MEDIUM">Medium+</option>
            <option value="LOW">Low+</option>
          </select>
          <span class="view-bar-label" style="margin-left:12px;">View as:</span>
          <button type="button" class="btn btn-secondary result-view-btn active" id="depViewList" onclick="setDepView('list')">List</button>
          <button type="button" class="btn btn-secondary result-view-btn" id="depViewTree" onclick="setDepView('tree')">Tree</button>
        </div>
        <div id="depFilterStatus" style="display:none;padding:8px 12px;margin-top:8px;margin-bottom:8px;background:rgba(136,192,208,0.1);border-radius:6px;font-size:0.85rem;color:var(--accent);"></div>
        <p class="dep-hint" style="margin-top:8px;font-size:0.85rem;color:var(--muted);">Click a dependency to see what it does, latest version, and its dependency tree.</p>
        <div id="depOverview"></div>
      </div>
    </div>

    <!-- Error state -->
    <div id="scanError" class="card hidden" style="border-color:var(--red);">
      <h2 style="color:var(--red);">Scan Error</h2>
      <p id="errorMsg" style="color:var(--muted);margin-top:8px;"></p>
    </div>
  </div>

  <!-- History Tab -->
  <div id="tab-history" class="hidden">
    <div class="card">
      <h2>Scan History</h2>
      <div id="historyLoading" class="loading"><div class="spinner"></div><div>Loading history...</div></div>
      <div id="historyEmpty" class="empty hidden"><p>No scan history yet. Run your first scan to get started.</p></div>
      <table class="history-table hidden" id="historyTable">
        <thead><tr><th>Date</th><th>Target</th><th>Deps</th><th>Vulns</th><th>Risk</th><th></th></tr></thead>
        <tbody id="historyBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Vulnerability detail modal -->
  <div id="vulnModal" class="overlay hidden">
    <div class="modal">
      <div class="modal-header">
        <h2 id="vulnModalTitle">Vulnerability</h2>
        <button type="button" class="modal-close" onclick="closeVulnModal()" aria-label="Close">&times;</button>
      </div>
      <div class="modal-body" id="vulnModalBody"></div>
    </div>
  </div>

  <!-- Dependency detail modal (click a library in Dependencies to open) -->
  <div id="depModal" class="overlay hidden">
    <div class="modal">
      <div class="modal-header">
        <h2 id="depModalTitle">Dependency</h2>
        <button type="button" class="modal-close" onclick="closeDepModal()" aria-label="Close">&times;</button>
      </div>
      <div class="modal-body" id="depModalBody"></div>
    </div>
  </div>
</div>

<script>
/* ── Helpers ── */
function esc(s) {
  if (!s) return "";
  var d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
function escAttr(s) {
  if (s == null) return "";
  var t = String(s);
  return t.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function byId(id) { return document.getElementById(id); }

/* ── State ── */
var currentReport = null;
var SEV_LIST = ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"];

/* ── Scan ── */
function runScan() {
  var targetEl = byId("targetInput");
  var btn = byId("scanBtn");
  var loadingEl = byId("scanLoading");
  var resultsEl = byId("scanResults");
  var errorEl = byId("scanError");
  var errorMsgEl = byId("errorMsg");

  var target = (targetEl && targetEl.value.trim()) || ".";
  var skipLicenses = byId("optSkipLicenses") ? byId("optSkipLicenses").checked : false;
  var skipDev = byId("optSkipDev") ? byId("optSkipDev").checked : false;

  if (btn) { btn.disabled = true; btn.textContent = "Scanning..."; }
  if (loadingEl) loadingEl.classList.remove("hidden");
  if (resultsEl) resultsEl.classList.add("hidden");
  if (errorEl) errorEl.classList.add("hidden");

  var apiBase = (typeof window !== "undefined" && window.location && window.location.origin) ? window.location.origin : "";
  fetch(apiBase + "/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: target, skipLicenses: skipLicenses, skipDev: skipDev })
  })
  .then(function(res) {
    return res.json()
      .then(function(d) { return { ok: res.ok, status: res.status, statusText: res.statusText, data: d }; })
      .catch(function() { return { ok: res.ok, status: res.status, statusText: res.statusText, data: {} }; });
  })
  .then(function(r) {
    if (!r.ok) throw new Error(r.data.error || "Scan failed: " + r.status + " " + r.statusText);
    if (r.data && r.data.error) throw new Error(r.data.error);
    var report = r.data;
    if (!report || typeof report !== "object") throw new Error("Invalid scan response from server");
    currentReport = report;
    renderResults(report);
    var el = byId("scanResults");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  })
  .catch(function(err) {
    if (errorEl) errorEl.classList.remove("hidden");
    var msg = err.message || String(err);
    if (msg.indexOf("Failed to fetch") !== -1 || msg.indexOf("NetworkError") !== -1) {
      msg = "Cannot reach server. Start SCATO with: node dist/index.js serve (or bun run serve)";
    }
    if (errorMsgEl) errorMsgEl.textContent = msg;
    var errEl = byId("scanError");
    if (errEl) errEl.scrollIntoView({ behavior: "smooth", block: "start" });
  })
  .then(function() {
    if (btn) { btn.disabled = false; btn.textContent = "Scan"; }
    if (loadingEl) loadingEl.classList.add("hidden");
  });
}

/* runScan is global */

/* ── Render consolidated advisory count badges for a vuln array ── */
function vulnSummaryBadges(vulns) {
  var counts = {};
  var kevCnt = 0;
  var i, s;
  for (i = 0; i < vulns.length; i++) {
    s = (vulns[i].severity || "UNKNOWN").toUpperCase();
    if (SEV_LIST.indexOf(s) === -1) s = "UNKNOWN";
    counts[s] = (counts[s] || 0) + 1;
    if (vulns[i].isKnownExploited) kevCnt++;
  }
  var out = '<span class="advisory-total">' + vulns.length + " advisor" + (vulns.length === 1 ? "y" : "ies") + "</span> ";
  if (kevCnt > 0) {
    out += '<span class="badge badge-kev">' + kevCnt + " KEV</span> ";
  }
  for (i = 0; i < SEV_LIST.length; i++) {
    if (counts[SEV_LIST[i]]) {
      out += '<span class="badge badge-' + SEV_LIST[i].toLowerCase() + '">';
      out += counts[SEV_LIST[i]] + " " + SEV_LIST[i] + "</span> ";
    }
  }
  return out;
}

var SEV_ORD = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

function getWorstSeverityIdx(result) {
  var vulns = result.vulnerabilities || [];
  var worst = 5;
  for (var i = 0; i < vulns.length; i++) {
    var s = vulns[i].severity;
    var idx = SEV_ORD[s];
    if (idx !== undefined && idx < worst) worst = idx;
  }
  return worst;
}

function hasSeverityAtLeast(result, minSev) {
  var minIdx = SEV_ORD[minSev];
  if (minIdx === undefined) return true;
  return getWorstSeverityIdx(result) <= minIdx;
}

function matchSearch(name, version, q) {
  if (!q) return true;
  q = q.trim().toLowerCase();
  if (!q) return true;
  var s = (name + " " + version).toLowerCase();
  return s.indexOf(q) !== -1;
}

/* Build vuln list HTML from filtered/sorted results */
function renderVulnList(vulnResults, allResults) {
  var vh = "";
  var ri, vi, si;
  if (vulnResults.length === 0) {
    vh = '<div class="empty"><p style="color:var(--muted);font-size:0.95rem;">No vulnerabilities match the current filter. Try changing the filter or sort options above.</p></div>';
    byId("resultsList").innerHTML = vh;
    return;
  }
  for (ri = 0; ri < vulnResults.length; ri++) {
    var res = vulnResults[ri];
    var ridx = allResults.indexOf(res);
    var dep = res.dependency;
    var dlabel = dep.isDirect ? "direct" : "transitive";
    vh += '<div class="result-item"><div class="result-header">';
    vh += "<div>";
    vh += '<span class="result-pkg">' + esc(dep.name) + "@" + esc(dep.version) + "</span> ";
    vh += '<span class="result-eco">' + esc(dep.ecosystem) + " &middot; " + dlabel + "</span>";
    vh += "</div>";
    vh += '<div class="result-badges">';
    for (si = 0; si < SEV_LIST.length; si++) {
      var cnt = 0;
      for (vi = 0; vi < res.vulnerabilities.length; vi++) {
        if (res.vulnerabilities[vi].severity === SEV_LIST[si]) cnt++;
      }
      if (cnt > 0) {
        vh += '<span class="badge badge-' + SEV_LIST[si].toLowerCase() + '">';
        vh += cnt + " " + SEV_LIST[si] + "</span>";
      }
    }
    vh += "</div></div>";
    vh += '<div class="vuln-list">';
    for (vi = 0; vi < res.vulnerabilities.length; vi++) {
      var vl = res.vulnerabilities[vi];
      var sv = (vl.severity || "UNKNOWN").toUpperCase();
      if (SEV_LIST.indexOf(sv) === -1) sv = "UNKNOWN";
      vh += '<div class="vuln-item vuln-item-clickable" data-result-idx="' + ridx + '" data-vuln-idx="' + vi + '" role="button" tabindex="0">';
      vh += '<span class="badge badge-' + sv.toLowerCase() + '">' + sv + "</span> ";
      if (vl.isKnownExploited) vh += '<span class="badge badge-kev">KEV</span> ';
      vh += '<span class="vuln-id">' + esc(vl.id) + "</span> ";
      var summ = vl.summary || "";
      vh += '<span class="vuln-summary">' + esc(summ.length > 120 ? summ.slice(0, 120) + "..." : summ) + "</span>";
      if (vl.fixed_version) vh += '<div class="vuln-fix">Fix: upgrade to ' + esc(vl.fixed_version) + "</div>";
      var meta = [];
      if (vl.score) meta.push("CVSS: " + vl.score);
      if (vl.epssScore) meta.push("EPSS: " + (vl.epssScore * 100).toFixed(1) + "%");
      if (vl.cwes && vl.cwes.length) meta.push(vl.cwes.slice(0, 2).join(", "));
      if (meta.length) vh += '<div class="vuln-meta">' + esc(meta.join(" | ")) + "</div>";
      vh += "</div>";
    }
    vh += "</div></div>";
  }
  byId("resultsList").innerHTML = vh;
}

/* Build dep overview HTML from direct + transitive lists */
function renderDepOverview(direct, transitive, parentMap) {
  var dh = "";
  var di, ki;
  if (direct.length === 0 && transitive.length === 0) {
    dh = '<div class="empty"><p style="color:var(--muted);font-size:0.95rem;">No dependencies match the current filter. Try changing the filter or sort options above.</p></div>';
    byId("depOverview").innerHTML = dh;
    return;
  }
  dh += '<div class="dep-section">';
  dh += '<div class="dep-section-title">Direct dependencies (' + direct.length + ")</div>";
  for (di = 0; di < direct.length; di++) {
    var dr = direct[di];
    var dd = dr.dependency;
    var dv = dr.vulnerabilities && dr.vulnerabilities.length > 0;
    var kids = parentMap[dd.name] || [];
    dh += '<div class="dep-group"><div class="dep-node dep-node-clickable direct' + (dv ? " has-vuln" : "") + '" data-dep-name="' + escAttr(dd.name) + '" data-dep-version="' + escAttr(dd.version) + '" data-dep-ecosystem="' + escAttr(dd.ecosystem) + '">';
    dh += '<div class="dep-name">' + esc(dd.name) + "@" + esc(dd.version) + "</div>";
    dh += '<div class="dep-meta">' + esc(dd.ecosystem);
    if (dd.license) dh += " &middot; " + esc(dd.license);
    dh += "</div>";
    if (dv) {
      dh += '<div class="result-badges" style="margin-top:8px;">';
      dh += vulnSummaryBadges(dr.vulnerabilities);
      dh += "</div>";
    }
    if (kids.length > 0) {
      dh += '<div class="dep-children">';
      for (ki = 0; ki < kids.length; ki++) {
        var kr = kids[ki];
        var kd = kr.dependency;
        var kv = kr.vulnerabilities && kr.vulnerabilities.length > 0;
        dh += '<div class="dep-child dep-child-clickable' + (kv ? " has-vuln" : "") + '" data-dep-name="' + escAttr(kd.name) + '" data-dep-version="' + escAttr(kd.version) + '" data-dep-ecosystem="' + escAttr(kd.ecosystem) + '">';
        dh += esc(kd.name) + "@" + esc(kd.version);
        dh += ' <span class="brought-in">(brought in by ' + esc(dd.name) + ")</span>";
        if (kv) {
          dh += " &mdash; ";
          dh += '<span class="badge badge-' + (kr.vulnerabilities[0].severity || "unknown").toLowerCase() + '">';
          dh += kr.vulnerabilities.length + " vuln(s)</span>";
        }
        dh += "</div>";
      }
      dh += "</div>";
    }
    dh += "</div></div>";
  }
  dh += "</div>";
  dh += '<div class="dep-section">';
  dh += '<div class="dep-section-title">Transitive dependencies (' + transitive.length + ")</div>";
  for (di = 0; di < transitive.length; di++) {
    var tr = transitive[di];
    var td = tr.dependency;
    var tv = tr.vulnerabilities && tr.vulnerabilities.length > 0;
    dh += '<div class="dep-group"><div class="dep-node dep-node-clickable' + (tv ? " has-vuln" : "") + '" data-dep-name="' + escAttr(td.name) + '" data-dep-version="' + escAttr(td.version) + '" data-dep-ecosystem="' + escAttr(td.ecosystem) + '">';
    dh += '<div class="dep-name">' + esc(td.name) + "@" + esc(td.version) + "</div>";
    dh += '<div class="dep-meta">' + esc(td.ecosystem);
    if (td.parent) dh += " &middot; brought in by " + esc(td.parent);
    dh += "</div>";
    if (tv) {
      dh += '<div class="result-badges" style="margin-top:8px;">';
      dh += vulnSummaryBadges(tr.vulnerabilities);
      dh += "</div>";
    }
    dh += "</div></div>";
  }
  dh += "</div>";
  byId("depOverview").innerHTML = dh;
}

function applyVulnFilters() {
  if (!currentReport || !currentReport.results) return;
  var all = currentReport.results || [];
  var vulnResults = [];
  for (var i = 0; i < all.length; i++) {
    if (all[i].vulnerabilities && all[i].vulnerabilities.length > 0) vulnResults.push(all[i]);
  }
  var searchEl = byId("vulnSearch");
  var sortEl = byId("vulnSort");
  var filterEl = byId("vulnFilter");
  var q = searchEl ? searchEl.value : "";
  var sortBy = sortEl ? sortEl.value : "severity";
  var minSev = filterEl ? filterEl.value : "";
  var filtered = [];
  for (i = 0; i < vulnResults.length; i++) {
    var r = vulnResults[i];
    var dep = r.dependency;
    if (!matchSearch(dep.name, dep.version, q)) continue;
    if (minSev === "KEV") {
      /* KEV only: at least one vuln must be isKnownExploited */
      var hasKev = false;
      for (var ki = 0; ki < r.vulnerabilities.length; ki++) {
        if (r.vulnerabilities[ki].isKnownExploited) { hasKev = true; break; }
      }
      if (!hasKev) continue;
    } else if (minSev && !hasSeverityAtLeast(r, minSev)) continue;
    filtered.push(r);
  }

  /* Helper: count KEV vulns in a result */
  function kevCount(r) {
    var c = 0;
    for (var j = 0; j < r.vulnerabilities.length; j++) {
      if (r.vulnerabilities[j].isKnownExploited) c++;
    }
    return c;
  }
  /* Helper: max EPSS score in a result */
  function maxEpss(r) {
    var m = 0;
    for (var j = 0; j < r.vulnerabilities.length; j++) {
      var e = r.vulnerabilities[j].epssScore || 0;
      if (e > m) m = e;
    }
    return m;
  }

  if (sortBy === "kev") {
    /* KEV first, then by severity */
    filtered.sort(function(a, b) {
      var ka = kevCount(a), kb = kevCount(b);
      if (ka !== kb) return kb - ka;
      return getWorstSeverityIdx(a) - getWorstSeverityIdx(b);
    });
  } else if (sortBy === "epss") {
    /* Highest EPSS score first */
    filtered.sort(function(a, b) {
      return maxEpss(b) - maxEpss(a);
    });
  } else if (sortBy === "name") {
    filtered.sort(function(a, b) {
      var na = (a.dependency.name + "@" + a.dependency.version).toLowerCase();
      var nb = (b.dependency.name + "@" + b.dependency.version).toLowerCase();
      return na < nb ? -1 : na > nb ? 1 : 0;
    });
  } else if (sortBy === "advisories") {
    filtered.sort(function(a, b) {
      var ac = a.vulnerabilities.length;
      var bc = b.vulnerabilities.length;
      return bc - ac;
    });
  } else {
    filtered.sort(function(a, b) {
      return getWorstSeverityIdx(a) - getWorstSeverityIdx(b);
    });
  }
  renderVulnList(filtered, all);
  /* Show active filter indicator */
  var vulnFilterStatus = byId("vulnFilterStatus");
  if (vulnFilterStatus) {
    if (minSev || q) {
      vulnFilterStatus.textContent = "Showing " + filtered.length + " of " + vulnResults.length + " vulnerable packages";
      vulnFilterStatus.style.display = "block";
    } else {
      vulnFilterStatus.style.display = "none";
    }
  }
}
/* applyVulnFilters is global */

function applyDepFilters() {
  if (!currentReport || !currentReport.results) return;
  var all = currentReport.results || [];
  var direct = [];
  var transitive = [];
  for (var i = 0; i < all.length; i++) {
    if (all[i].dependency.isDirect) direct.push(all[i]); else transitive.push(all[i]);
  }
  var searchEl = byId("depSearch");
  var sortEl = byId("depSort");
  var filterEl = byId("depFilter");
  var q = searchEl ? searchEl.value : "";
  var sortBy = sortEl ? sortEl.value : "advisories";
  var filterVal = filterEl ? filterEl.value : "";
  function depHasKev(r) {
    if (!r.vulnerabilities) return false;
    for (var x = 0; x < r.vulnerabilities.length; x++) {
      if (r.vulnerabilities[x].isKnownExploited) return true;
    }
    return false;
  }
  function depKevCount(r) {
    var c = 0;
    if (!r.vulnerabilities) return 0;
    for (var x = 0; x < r.vulnerabilities.length; x++) {
      if (r.vulnerabilities[x].isKnownExploited) c++;
    }
    return c;
  }
  function filterList(list) {
    var out = [];
    for (var j = 0; j < list.length; j++) {
      var r = list[j];
      var dep = r.dependency;
      if (!matchSearch(dep.name, dep.version, q)) continue;
      if (filterVal === "KEV") {
        if (!depHasKev(r)) continue;
      } else if (filterVal === "hasVuln") {
        if (!r.vulnerabilities || r.vulnerabilities.length === 0) continue;
      } else if (filterVal && filterVal !== "hasVuln") {
        if (!r.vulnerabilities || r.vulnerabilities.length === 0) continue;
        if (!hasSeverityAtLeast(r, filterVal)) continue;
      }
      out.push(r);
    }
    return out;
  }
  direct = filterList(direct);
  transitive = filterList(transitive);
  function sortList(list) {
    if (sortBy === "kev") {
      list.sort(function(a, b) {
        var ka = depKevCount(a), kb = depKevCount(b);
        if (ka !== kb) return kb - ka;
        var ac = (a.vulnerabilities && a.vulnerabilities.length) || 0;
        var bc = (b.vulnerabilities && b.vulnerabilities.length) || 0;
        return bc - ac;
      });
    } else if (sortBy === "name") {
      list.sort(function(a, b) {
        var na = (a.dependency.name + "@" + a.dependency.version).toLowerCase();
        var nb = (b.dependency.name + "@" + b.dependency.version).toLowerCase();
        return na < nb ? -1 : na > nb ? 1 : 0;
      });
    } else if (sortBy === "advisories") {
      list.sort(function(a, b) {
        var ac = (a.vulnerabilities && a.vulnerabilities.length) || 0;
        var bc = (b.vulnerabilities && b.vulnerabilities.length) || 0;
        return bc - ac;
      });
    } else {
      list.sort(function(a, b) {
        return getWorstSeverityIdx(a) - getWorstSeverityIdx(b);
      });
    }
  }
  sortList(direct);
  sortList(transitive);
  var parentMap = {};
  for (i = 0; i < transitive.length; i++) {
    var pn = transitive[i].dependency.parent || "";
    if (!parentMap[pn]) parentMap[pn] = [];
    parentMap[pn].push(transitive[i]);
  }
  renderDepOverview(direct, transitive, parentMap);
  /* Show active filter indicator */
  var depFilterStatus = byId("depFilterStatus");
  if (depFilterStatus) {
    var totalAll = 0;
    for (i = 0; i < all.length; i++) totalAll++;
    if (filterVal || q) {
      depFilterStatus.textContent = "Showing " + (direct.length + transitive.length) + " of " + totalAll + " packages" + (filterVal === "KEV" ? " (KEV filter active)" : "");
      depFilterStatus.style.display = "block";
    } else {
      depFilterStatus.style.display = "none";
    }
  }
}
/* applyDepFilters is global */

var depViewMode = "list";

function setDepView(mode) {
  depViewMode = mode;
  var listBtn = byId("depViewList");
  var treeBtn = byId("depViewTree");
  if (listBtn) listBtn.classList.toggle("active", mode === "list");
  if (treeBtn) treeBtn.classList.toggle("active", mode === "tree");
  if (mode === "tree") renderDepTree(); else applyDepFilters();
}
/* setDepView is global */

function toggleDepTreeChild(el) {
  var par = el.parentNode;
  if (!par || !par.nextElementSibling) return;
  var ch = par.nextElementSibling;
  ch.classList.toggle("collapsed");
  var tgl = el.querySelector(".dep-tree-toggle");
  if (tgl && !tgl.classList.contains("empty")) tgl.textContent = ch.classList.contains("collapsed") ? "\u25B6" : "\u25BC";
}

function toggleTreeNode(btn) {
  var id = btn.getAttribute('data-tree-id');
  if (!id) return;
  var el = byId(id);
  if (!el) return;
  var isHidden = el.style.display === 'none';
  el.style.display = isHidden ? '' : 'none';
  btn.textContent = isHidden ? '\u25BC' : '\u25B6';
}

function renderDepTree() {
  var container = byId("depOverview");
  if (!container) return;
  if (!currentReport || !currentReport.dependencyTrees || currentReport.dependencyTrees.length === 0) {
    container.innerHTML = '<p class="empty" style="color:var(--muted);">No tree data. Run a scan with a lockfile (package-lock.json or bun.lock).</p>';
    return;
  }
  var vulnMap = {};
  var results = currentReport.results || [];
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    var k = r.dependency.ecosystem + ":" + r.dependency.name + "@" + r.dependency.version;
    vulnMap[k] = (r.vulnerabilities && r.vulnerabilities.length) || 0;
  }

  /* Build lines like a terminal tree (similar to the tree command):
     project
     \u251C\u2500\u2500 ora@8.2.0
     \u2502   \u251C\u2500\u2500 chalk@5.3.0
     \u2502   \u2514\u2500\u2500 cli-cursor@5.0.0
     \u2502       \u2514\u2500\u2500 restore-cursor@5.1.0
     \u2514\u2500\u2500 hono@4.11.8
  */
  var _treeIdCounter = 0;
  function nodeLines(node, prefix, isLast) {
    var d = node.dependency;
    var k = d.ecosystem + ":" + d.name + "@" + d.version;
    var vc = vulnMap[k] || 0;
    var hasKids = node.children && node.children.length > 0;
    var connector = isLast ? '\u2514\u2500\u2500 ' : '\u251C\u2500\u2500 ';
    var nodeId = 'dtree_' + (_treeIdCounter++);
    var cls = vc > 0 ? ' has-vuln' : '';
    var badgeHtml = vc > 0 ? ' <span class="dep-tree-badge">' + vc + ' vuln' + (vc === 1 ? '' : 's') + '</span>' : '';
    var toggleHtml = hasKids ? ' <span class="dep-tree-toggle-btn" data-tree-id="' + nodeId + '">\u25BC</span>' : '';

    var line = '<span class="dep-tree-line">';
    line += '<span class="dep-tree-connector">' + esc(prefix + connector) + '</span>';
    line += '<span class="dep-tree-pkg' + cls + '" data-dep-name="' + escAttr(d.name) + '" data-dep-version="' + escAttr(d.version) + '" data-dep-ecosystem="' + escAttr(d.ecosystem) + '">';
    line += esc(d.name);
    line += '</span>';
    line += '<span class="dep-tree-ver">@' + esc(d.version) + '</span>';
    line += badgeHtml + toggleHtml;
    line += '</span>' + String.fromCharCode(10);

    if (hasKids) {
      var childPrefix = prefix + (isLast ? '    ' : '\u2502   ');
      line += '<span id="' + nodeId + '">';
      for (var j = 0; j < node.children.length; j++) {
        var childIsLast = (j === node.children.length - 1);
        line += nodeLines(node.children[j], childPrefix, childIsLast);
      }
      line += '</span>';
    }
    return line;
  }

  var html = '';
  for (var t = 0; t < currentReport.dependencyTrees.length; t++) {
    var tr = currentReport.dependencyTrees[t];
    html += '<div class="dep-tree-eco">';
    html += '<div class="dep-tree-eco-title">' + esc(tr.ecosystem) + ' \u2014 ' + tr.directCount + ' direct, ' + tr.transitiveCount + ' transitive, depth ' + tr.maxDepth + '</div>';
    html += '<div class="dep-tree-root">';
    /* Root line */
    html += '<span class="dep-tree-line"><span class="dep-tree-connector">\u25CF </span><span style="color:var(--green);font-weight:600;">project</span> <span class="dep-tree-ver">(' + tr.totalCount + ' packages)</span></span>' + String.fromCharCode(10);
    for (var n = 0; n < tr.nodes.length; n++) {
      var rootIsLast = (n === tr.nodes.length - 1);
      html += nodeLines(tr.nodes[n], '', rootIsLast);
    }
    html += '</div></div>';
  }
  container.innerHTML = html;
}
/* renderDepTree is global */

/* ── Render results ── */
/* ── Prioritized Remediation Engine (client-side) ── */
/* Mirrors server: max + dampened sum, exponential severity, KEV multiplier, tie-break by CVE count. */
function computeRemediation(vulnResults) {
  var WEIGHT_KEV = 30, WEIGHT_EPSS = 20, WEIGHT_VECTOR = 15, WEIGHT_SEV = 30, WEIGHT_FIX = 5;
  var MAX_SCORE_PER_VULN = WEIGHT_KEV + WEIGHT_EPSS + WEIGHT_VECTOR + WEIGHT_SEV + WEIGHT_FIX;
  var DAMPENER = 0.1;
  var KEV_MULTIPLIER = 2.5;
  var SEV_SCORE = { CRITICAL: 1.0, HIGH: 0.5, MEDIUM: 0.15, LOW: 0.03, UNKNOWN: 0.01 };

  function scoreVuln(v) {
    var s = 0;
    var breakdown = { kev: 0, epss: 0, vector: 0, severity: 0, fix: 0 };
    if (v.isKnownExploited) { s += WEIGHT_KEV; breakdown.kev = WEIGHT_KEV; }
    var epssContrib = (v.epssScore || 0) * WEIGHT_EPSS;
    s += epssContrib; breakdown.epss = Math.round(epssContrib * 100) / 100;
    var vec = v.cvssVector || '';
    var vs = 0;
    if (vec.indexOf('AV:N') !== -1) vs += 0.4; else if (vec.indexOf('AV:A') !== -1) vs += 0.24; else vs += 0.15;
    if (vec.indexOf('AC:L') !== -1) vs += 0.3; else vs += 0.1;
    if (vec.indexOf('UI:N') !== -1) vs += 0.2; else vs += 0.05;
    if (vec.indexOf('S:C') !== -1) vs += 0.1;
    var vecContrib = Math.min(1.0, vs) * WEIGHT_VECTOR;
    s += vecContrib; breakdown.vector = Math.round(vecContrib * 100) / 100;
    var sevKey = (v.severity || 'UNKNOWN').toUpperCase();
    var sevContrib = (SEV_SCORE[sevKey] || 0.01) * WEIGHT_SEV;
    s += sevContrib; breakdown.severity = Math.round(sevContrib * 100) / 100;
    if (v.fixed_version) { s += WEIGHT_FIX; breakdown.fix = WEIGHT_FIX; }
    return { score: Math.round(s * 100) / 100, breakdown: breakdown };
  }

  function isNetworkRce(v) {
    var vec = v.cvssVector || '';
    if (vec.indexOf('AV:N') === -1) return false;
    return vec.indexOf('C:H') !== -1 && vec.indexOf('I:H') !== -1;
  }

  function attackVector(v) {
    var vec = v.cvssVector || '';
    if (vec.indexOf('AV:N') !== -1) return 'Network';
    if (vec.indexOf('AV:A') !== -1) return 'Adjacent';
    if (vec.indexOf('AV:L') !== -1) return 'Local';
    if (vec.indexOf('AV:P') !== -1) return 'Physical';
    return 'Unknown';
  }

  function formatRiskDominator(topCve, sevStr, av) {
    var rce = (av === 'Network' && (topCve.cvss >= 9 || sevStr === 'CRITICAL' || sevStr === 'HIGH')) ? ' RCE' : '';
    return '1 ' + sevStr + rce + ' (' + av + ')';
  }

  var totalRiskScore = 0;
  var totalVulnCount = 0;
  var totalKevCount = 0;
  var totalCritCount = 0;
  var totalHighCount = 0;

  var actions = [];
  for (var i = 0; i < vulnResults.length; i++) {
    var res = vulnResults[i];
    var dep = res.dependency;
    var vulns = res.vulnerabilities;
    if (!vulns || vulns.length === 0) continue;

    var kc = 0, mEpss = 0, mCvss = 0, netRce = false;
    var sc = {}, cveList = [], breakdowns = [];
    var bestFix = null, fixCoverage = 0;
    var avSet = {};
    var cveScores = [];

    for (var j = 0; j < vulns.length; j++) {
      var v = vulns[j];
      var scored = scoreVuln(v);
      cveScores.push(scored.score);
      breakdowns.push(scored.breakdown);
      if (v.isKnownExploited) kc++;
      if ((v.epssScore || 0) > mEpss) mEpss = v.epssScore || 0;
      if ((v.score || 0) > mCvss) mCvss = v.score || 0;
      if (isNetworkRce(v)) netRce = true;
      var sv = (v.severity || 'UNKNOWN').toUpperCase();
      sc[sv] = (sc[sv] || 0) + 1;
      if (v.fixed_version) { bestFix = v.fixed_version; fixCoverage++; }
      avSet[attackVector(v)] = true;
      cveList.push({
        id: v.id || (v.aliases && v.aliases[0]) || 'N/A',
        severity: sv,
        cvss: v.score || 0,
        epss: v.epssScore || 0,
        kev: !!v.isKnownExploited,
        vector: v.cvssVector || 'N/A',
        fix: v.fixed_version || null,
        score: scored.score,
        attackVector: attackVector(v)
      });

      totalVulnCount++;
      if (v.isKnownExploited) totalKevCount++;
      if (sv === 'CRITICAL') totalCritCount++;
      if (sv === 'HIGH') totalHighCount++;
    }

    /* Aggregation: max + dampened sum */
    cveScores.sort(function(a, b) { return b - a; });
    var maxScore = cveScores[0] || 0;
    var restSum = 0;
    for (j = 1; j < cveScores.length; j++) restSum += cveScores[j];
    var baseRiskScore = Math.round((maxScore + restSum * DAMPENER) * 100) / 100;
    var hasKEV = kc > 0;
    var pkgScore = Math.round((hasKEV ? baseRiskScore * KEV_MULTIPLIER : baseRiskScore) * 100) / 100;
    totalRiskScore += pkgScore;

    var pkgBreakdown = { kev: 0, epss: 0, vector: 0, severity: 0, fix: 0 };
    for (j = 0; j < breakdowns.length; j++) {
      pkgBreakdown.kev += breakdowns[j].kev;
      pkgBreakdown.epss += breakdowns[j].epss;
      pkgBreakdown.vector += breakdowns[j].vector;
      pkgBreakdown.severity += breakdowns[j].severity;
      pkgBreakdown.fix += breakdowns[j].fix;
    }

    cveList.sort(function(a, b) { return b.score - a.score; });
    var topCve = cveList[0];
    var riskDominator = topCve ? formatRiskDominator(topCve, topCve.severity, topCve.attackVector) : 'No CVEs';

    actions.push({
      name: dep.name, ver: dep.version, eco: dep.ecosystem,
      fix: bestFix, isDirect: dep.isDirect, parent: dep.parent,
      count: vulns.length, sev: sc, kev: kc, epss: mEpss,
      cvss: mCvss, rce: netRce, pkgScore: pkgScore, baseRiskScore: baseRiskScore,
      cves: cveList, fixCoverage: fixCoverage,
      attackVectors: Object.keys(avSet),
      breakdown: pkgBreakdown,
      riskDominator: riskDominator
    });
  }

  totalRiskScore = Math.round(totalRiskScore * 100) / 100;

  for (i = 0; i < actions.length; i++) {
    actions[i].roi = totalRiskScore > 0 ? Math.round(actions[i].pkgScore / totalRiskScore * 1000) / 10 : 0;
  }

  actions.sort(function(a, b) {
    if (a.kev > 0 && b.kev === 0) return -1;
    if (b.kev > 0 && a.kev === 0) return 1;
    if (b.pkgScore !== a.pkgScore) return b.pkgScore - a.pkgScore;
    if (b.epss !== a.epss) return b.epss - a.epss;
    return a.count - b.count;
  });

  return {
    actions: actions.slice(0, 5),
    totalRiskScore: totalRiskScore,
    totalVulnCount: totalVulnCount,
    totalKevCount: totalKevCount,
    totalCritCount: totalCritCount,
    totalHighCount: totalHighCount,
    totalPackages: vulnResults.length,
    maxScorePerVuln: MAX_SCORE_PER_VULN
  };
}

function renderRemediation(vulnResults) {
  var card = byId('remediationCard');
  var actionsEl = byId('remediationActions');
  var summaryBox = byId('remediationSummaryBox');
  if (!card || !actionsEl) return;

  var rem = computeRemediation(vulnResults);
  if (rem.actions.length === 0) { card.classList.add('hidden'); return; }
  card.classList.remove('hidden');

  /* ── Quantified Summary ── */
  var topFixCount = 0, topRoi = 0, topKev = 0, topCves = 0;
  for (var i = 0; i < rem.actions.length; i++) {
    topFixCount += rem.actions[i].count;
    topRoi += rem.actions[i].roi;
    topKev += rem.actions[i].kev;
    topCves += rem.actions[i].cves.length;
  }

  var sh = '';
  sh += '<div style="font-size:0.85rem;color:var(--muted);margin-bottom:8px;">';
  sh += 'Fixing <strong style="color:var(--text);">' + rem.actions.length + '</strong> packages resolves ';
  sh += '<strong style="color:var(--text);">' + topFixCount + '</strong> of <strong style="color:var(--text);">' + rem.totalVulnCount + '</strong> vulnerabilities ';
  sh += '(<strong style="color:var(--green);">' + Math.round(topRoi) + '% risk reduction</strong>)';
  sh += '</div>';
  sh += '<div class="remediation-summary-grid">';
  sh += '<div class="remediation-summary-stat"><div class="val" style="color:var(--red);">' + rem.totalRiskScore.toFixed(1) + '</div><div class="lbl">Total Risk Score</div></div>';
  sh += '<div class="remediation-summary-stat"><div class="val">' + rem.totalVulnCount + '</div><div class="lbl">Total CVEs</div></div>';
  sh += '<div class="remediation-summary-stat"><div class="val" style="color:var(--orange);">' + rem.totalKevCount + '</div><div class="lbl">KEV (Exploited)</div></div>';
  sh += '<div class="remediation-summary-stat"><div class="val" style="color:var(--red);">' + rem.totalCritCount + '</div><div class="lbl">Critical</div></div>';
  sh += '<div class="remediation-summary-stat"><div class="val" style="color:var(--orange);">' + rem.totalHighCount + '</div><div class="lbl">High</div></div>';
  sh += '<div class="remediation-summary-stat"><div class="val" style="color:var(--green);">' + rem.maxScorePerVuln + '</div><div class="lbl">Max Score/CVE</div></div>';
  sh += '</div>';
  if (summaryBox) summaryBox.innerHTML = sh;

  /* ── Per-Action Detailed Cards ── */
  var html = '';
  for (i = 0; i < rem.actions.length; i++) {
    var a = rem.actions[i];
    var rank = i + 1;

    html += '<div class="remediation-action">';

    /* Header: rank, name, metrics */
    html += '<div class="remediation-action-header">';
    html += '<div style="display:flex;gap:12px;align-items:flex-start;">';
    html += '<span class="remediation-rank">' + rank + '</span>';
    html += '<div class="remediation-action-left">';
    html += '<div class="remediation-action-pkg">' + esc(a.name) + '@' + esc(a.ver) + ' <span style="font-size:0.72rem;font-weight:400;color:var(--muted);background:rgba(136,192,208,0.12);padding:1px 6px;border-radius:4px;margin-left:6px;">' + esc(a.eco) + '</span></div>';
    if (a.fix) {
      html += '<div class="remediation-action-upgrade">';
      html += 'Fix version: <strong>' + esc(a.fix) + '</strong>';
      html += ' (' + a.fixCoverage + '/' + a.count + ' CVEs patched)';
      html += '</div>';
    } else {
      html += '<div style="color:var(--muted);font-size:0.9rem;">No fix version available &mdash; consider removing or replacing</div>';
    }
    html += '<div class="remediation-latest-ver" id="rem-latest-' + rank + '" style="font-size:0.85rem;color:var(--muted);margin-top:2px;">';
    html += '<span style="opacity:0.6;">Latest: </span><span class="rem-latest-val" style="color:var(--accent);">loading...</span>';
    html += '</div>';
    if (a.riskDominator) {
      html += '<div class="remediation-risk-dominator" style="margin-top:6px;font-size:0.8rem;color:var(--muted);">';
      html += '<span style="opacity:0.8;">Driven by: </span><strong style="color:var(--text);">' + esc(a.riskDominator) + '</strong>';
      html += '</div>';
    }
    html += '</div></div>';

    /* Right side: quantified metrics */
    html += '<div class="remediation-action-right">';
    html += '<div class="remediation-metric metric-risk"><span class="m-val">' + a.pkgScore.toFixed(1) + '</span><span class="m-lbl">Risk Score</span></div>';
    html += '<div class="remediation-metric metric-roi"><span class="m-val">' + a.roi + '%</span><span class="m-lbl">Risk Reduction</span></div>';
    if (a.cvss > 0) html += '<div class="remediation-metric metric-cvss"><span class="m-val">' + a.cvss.toFixed(1) + '</span><span class="m-lbl">CVSS (max)</span></div>';
    if (a.epss > 0) html += '<div class="remediation-metric metric-epss"><span class="m-val">' + (a.epss * 100).toFixed(1) + '%</span><span class="m-lbl">EPSS (max)</span></div>';
    html += '</div></div>';

    /* Badges */
    html += '<div class="remediation-badges">';
    if (a.kev > 0) html += '<span class="badge badge-kev">' + a.kev + ' CISA KEV</span>';
    if (a.rce) html += '<span class="badge badge-critical">Network RCE</span>';
    if (a.sev['CRITICAL']) html += '<span class="badge badge-critical">' + a.sev['CRITICAL'] + ' Critical</span>';
    if (a.sev['HIGH']) html += '<span class="badge badge-high">' + a.sev['HIGH'] + ' High</span>';
    if (a.sev['MEDIUM']) html += '<span class="badge badge-medium">' + a.sev['MEDIUM'] + ' Medium</span>';
    if (a.sev['LOW']) html += '<span class="badge badge-low">' + a.sev['LOW'] + ' Low</span>';
    html += '<span class="badge" style="background:rgba(136,192,208,0.15);color:var(--accent);">Vectors: ' + a.attackVectors.join(', ') + '</span>';
    if (!a.isDirect && a.parent) html += '<span class="badge badge-unknown">Transitive via ' + esc(a.parent) + '</span>';
    if (a.isDirect) html += '<span class="badge" style="background:rgba(63,185,80,0.15);color:var(--green);">Direct dependency</span>';
    html += '</div>';

    /* Quantified Analysis */
    html += '<div class="remediation-analysis"><dl>';

    /* Base vs adjusted risk (when KEV boost applied) */
    if (a.kev > 0 && a.baseRiskScore !== undefined && a.baseRiskScore > 0 && a.pkgScore > a.baseRiskScore) {
      html += '<dt>Risk score</dt>';
      html += '<dd>Base risk (max + dampened sum): <strong>' + a.baseRiskScore.toFixed(1) + '</strong>. ';
      html += 'Adjusted with KEV multiplier for ROI alignment: <strong>' + a.pkgScore.toFixed(1) + '</strong>.</dd>';
    }

    /* Score Breakdown */
    html += '<dt>Score Breakdown (component contributions; base risk ' + (a.baseRiskScore != null ? a.baseRiskScore.toFixed(1) : a.pkgScore.toFixed(1)) + ')</dt>';
    html += '<dd>';
    var bk = a.breakdown;
    var totalBk = bk.kev + bk.epss + bk.vector + bk.severity + bk.fix;
    var pctDenom = totalBk > 0 ? totalBk : 1;
    var bkParts = [];
    if (bk.kev > 0) bkParts.push('KEV: ' + bk.kev.toFixed(1) + ' (' + Math.round(bk.kev / pctDenom * 100) + '%)');
    if (bk.epss > 0) bkParts.push('EPSS: ' + bk.epss.toFixed(1) + ' (' + Math.round(bk.epss / pctDenom * 100) + '%)');
    if (bk.vector > 0) bkParts.push('Attack Vector: ' + bk.vector.toFixed(1) + ' (' + Math.round(bk.vector / pctDenom * 100) + '%)');
    if (bk.severity > 0) bkParts.push('Severity: ' + bk.severity.toFixed(1) + ' (' + Math.round(bk.severity / pctDenom * 100) + '%)');
    if (bk.fix > 0) bkParts.push('Fix Available: ' + bk.fix.toFixed(1) + ' (' + Math.round(bk.fix / pctDenom * 100) + '%)');
    html += bkParts.join(' &middot; ');
    html += '</dd>';

    /* Risk Reduction */
    html += '<dt>Risk Reduction</dt>';
    html += '<dd>Remediating ' + esc(a.name) + ' removes <strong>' + a.pkgScore.toFixed(1) + '</strong> of <strong>' + rem.totalRiskScore.toFixed(1) + '</strong> total risk points (<strong>' + a.roi + '%</strong>). ';
    if (a.fix) {
      html += 'Upgrading from ' + esc(a.ver) + ' to ' + esc(a.fix) + ' patches ' + a.fixCoverage + ' of ' + a.count + ' known vulnerabilities. ';
      html += 'Latest registry version: <span id="rem-analysis-latest-' + rank + '" style="color:var(--accent);">resolving...</span>';
    } else {
      html += 'No fix is available. Evaluate alternative packages or apply compensating controls (WAF rules, network segmentation).';
    }
    html += '</dd>';

    /* Threat Intelligence */
    html += '<dt>Threat Intelligence</dt><dd>';
    var ti = [];
    if (a.kev > 0) ti.push(a.kev + ' CVE' + (a.kev > 1 ? 's' : '') + ' confirmed actively exploited (CISA KEV catalog)');
    if (a.epss > 0) ti.push('Highest EPSS probability: ' + (a.epss * 100).toFixed(1) + '% chance of exploitation within 30 days');
    if (a.rce) ti.push('Contains network-accessible Remote Code Execution (AV:N + C:H + I:H)');
    if (ti.length === 0) ti.push('No active exploitation data available. Prioritization based on severity and attack vector analysis.');
    html += ti.join('. ') + '.';
    html += '</dd>';

    /* CVE Detail Table */
    if (a.cves.length > 0) {
      html += '<dt>CVE Breakdown (' + a.cves.length + ' total)</dt><dd>';
      html += '<table style="width:100%;border-collapse:collapse;font-size:0.8rem;margin-top:4px;">';
      html += '<tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;padding:3px 8px 3px 0;color:var(--muted);">CVE</th>';
      html += '<th style="text-align:center;padding:3px 8px;color:var(--muted);">Severity</th>';
      html += '<th style="text-align:center;padding:3px 8px;color:var(--muted);">CVSS</th>';
      html += '<th style="text-align:center;padding:3px 8px;color:var(--muted);">EPSS</th>';
      html += '<th style="text-align:center;padding:3px 8px;color:var(--muted);">KEV</th>';
      html += '<th style="text-align:center;padding:3px 8px;color:var(--muted);">Score</th>';
      html += '<th style="text-align:left;padding:3px 0 3px 8px;color:var(--muted);">Fix</th></tr>';
      for (var c = 0; c < a.cves.length; c++) {
        var cve = a.cves[c];
        var rowBg = c % 2 === 0 ? '' : 'background:rgba(136,192,208,0.04);';
        html += '<tr style="' + rowBg + 'border-bottom:1px solid rgba(136,192,208,0.08);">';
        html += '<td style="padding:4px 8px 4px 0;font-family:monospace;font-size:0.78rem;">' + esc(cve.id) + '</td>';
        var sevColor = cve.severity === 'CRITICAL' ? 'var(--red)' : cve.severity === 'HIGH' ? 'var(--orange)' : cve.severity === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)';
        html += '<td style="text-align:center;padding:4px 8px;color:' + sevColor + ';">' + cve.severity + '</td>';
        html += '<td style="text-align:center;padding:4px 8px;font-weight:600;">' + cve.cvss.toFixed(1) + '</td>';
        html += '<td style="text-align:center;padding:4px 8px;">' + (cve.epss > 0 ? (cve.epss * 100).toFixed(1) + '%' : 'N/A') + '</td>';
        html += '<td style="text-align:center;padding:4px 8px;">' + (cve.kev ? '<span style="color:var(--red);font-weight:700;">YES</span>' : 'No') + '</td>';
        html += '<td style="text-align:center;padding:4px 8px;font-weight:700;">' + cve.score.toFixed(1) + '<span style="color:var(--muted);font-weight:400;">/' + rem.maxScorePerVuln + '</span></td>';
        html += '<td style="padding:4px 0 4px 8px;">' + (cve.fix ? '<span style="color:var(--green);">' + esc(cve.fix) + '</span>' : '<span style="color:var(--muted);">None</span>') + '</td>';
        html += '</tr>';
      }
      html += '</table>';
      html += '</dd>';
    }

    html += '</dl></div>';
    html += '</div>';
  }
  actionsEl.innerHTML = html;

  /* ── Async: fetch latest version for each package from registry ── */
  for (i = 0; i < rem.actions.length; i++) {
    (function(idx, action) {
      var rank = idx + 1;
      var url = '/api/package-info?ecosystem=' + encodeURIComponent(action.eco) + '&name=' + encodeURIComponent(action.name);
      fetch(url).then(function(r) { return r.json(); }).then(function(data) {
        var el = byId('rem-latest-' + rank);
        if (!el) return;
        var valEl = el.querySelector('.rem-latest-val');
        if (!valEl) return;
        if (data.latestVersion) {
          var isBehind = data.latestVersion !== action.ver;
          var majorsBehind = '';
          if (isBehind) {
            var curParts = action.ver.split('.').map(Number);
            var latParts = data.latestVersion.split('.').map(Number);
            var majDiff = (latParts[0] || 0) - (curParts[0] || 0);
            var minDiff = (latParts[1] || 0) - (curParts[1] || 0);
            var patDiff = (latParts[2] || 0) - (curParts[2] || 0);
            if (majDiff > 0) majorsBehind = ' (' + majDiff + ' major' + (majDiff > 1 ? 's' : '') + ' behind)';
            else if (minDiff > 0) majorsBehind = ' (' + minDiff + ' minor' + (minDiff > 1 ? 's' : '') + ' behind)';
            else if (patDiff > 0) majorsBehind = ' (' + patDiff + ' patch' + (patDiff > 1 ? 'es' : '') + ' behind)';
          }
          valEl.innerHTML = '<strong>' + esc(data.latestVersion) + '</strong>';
          if (isBehind) {
            valEl.innerHTML += '<span style="color:var(--orange);font-size:0.78rem;margin-left:6px;">' + majorsBehind + '</span>';
          } else {
            valEl.innerHTML += '<span style="color:var(--green);font-size:0.78rem;margin-left:6px;">(up to date)</span>';
          }
          /* Also update analysis section */
          var analysisEl = byId('rem-analysis-latest-' + rank);
          if (analysisEl) {
            analysisEl.innerHTML = '<strong>' + esc(data.latestVersion) + '</strong>';
            if (isBehind) {
              analysisEl.innerHTML += '<span style="color:var(--orange);">' + majorsBehind + '</span>';
            }
          }
        } else {
          valEl.textContent = 'N/A';
        }
      }).catch(function() {
        var el = byId('rem-latest-' + rank);
        if (el) {
          var valEl = el.querySelector('.rem-latest-val');
          if (valEl) valEl.textContent = 'unavailable';
        }
      });
    })(i, rem.actions[i]);
  }
}

function renderResults(report) {
  try {
    var resultsPanel = byId("scanResults");
    var errPanel = byId("scanError");
    if (!resultsPanel) return;
    resultsPanel.classList.remove("hidden");
    if (errPanel) errPanel.classList.add("hidden");

    var all = report.results || [];
    if (!Array.isArray(all)) all = [];

    /* Stats */
    var sc = report.severityCounts || {};
    /* Count KEV vulns across all results */
    var totalKev = 0;
    for (var ki = 0; ki < all.length; ki++) {
      var kvs = all[ki].vulnerabilities || [];
      for (var kj = 0; kj < kvs.length; kj++) {
        if (kvs[kj].isKnownExploited) totalKev++;
      }
    }
    var stats = [
      { v: report.totalDependencies, l: "Dependencies", c: "" },
      { v: report.totalVulnerabilities, l: "Vulnerabilities", c: report.totalVulnerabilities > 0 ? "critical" : "ok" },
      { v: totalKev, l: "KEV (Exploited)", c: totalKev > 0 ? "critical" : "ok" },
      { v: sc.CRITICAL || 0, l: "Critical", c: "critical" },
      { v: sc.HIGH || 0, l: "High", c: "high" },
      { v: sc.MEDIUM || 0, l: "Medium", c: "medium" },
      { v: sc.LOW || 0, l: "Low", c: "low" }
    ];
    var statsHtml = "";
    var si;
    for (si = 0; si < stats.length; si++) {
      statsHtml += '<div class="stat ' + stats[si].c + '">';
      statsHtml += '<div class="value">' + stats[si].v + "</div>";
      statsHtml += '<div class="label">' + stats[si].l + "</div></div>";
    }
    byId("statsGrid").innerHTML = statsHtml;

    /* Risk */
    var risk = (report.metrics && report.metrics.riskScore) || 0;
    var rc = risk >= 80 ? "var(--red)" : risk >= 60 ? "var(--orange)" : risk >= 30 ? "var(--yellow)" : "var(--green)";
    byId("riskBar").style.width = risk + "%";
    byId("riskBar").style.background = rc;
    byId("riskLabel").textContent = risk + "/100";
    byId("riskLabel").style.color = rc;

    /* Dependency overview */
    var direct = [];
    var transitive = [];
    var di;
    for (di = 0; di < all.length; di++) {
      if (all[di].dependency.isDirect) { direct.push(all[di]); } else { transitive.push(all[di]); }
    }
    var parentMap = {};
    for (di = 0; di < transitive.length; di++) {
      var pn = transitive[di].dependency.parent || "";
      if (!parentMap[pn]) parentMap[pn] = [];
      parentMap[pn].push(transitive[di]);
    }

    renderDepOverview(direct, transitive, parentMap);

    var noDepsHint = byId("noDepsHint");
    if (noDepsHint) {
      if (all.length === 0) {
        noDepsHint.textContent = 'No dependencies found. Use an absolute path to your project (e.g. /Users/you/myproject) or start the server from your project folder and use "."';
        noDepsHint.classList.remove("hidden");
      } else {
        noDepsHint.textContent = "";
        noDepsHint.classList.add("hidden");
      }
    }

    /* Vuln list */
    var vulnResults = [];
    for (di = 0; di < all.length; di++) {
      if (all[di].vulnerabilities && all[di].vulnerabilities.length > 0) {
        vulnResults.push(all[di]);
      }
    }
    byId("vulnTitle").textContent = report.totalVulnerabilities === 0
      ? "No Vulnerabilities Found"
      : "Vulnerabilities (" + report.totalVulnerabilities + ")";

    if (vulnResults.length === 0) {
      byId("resultsList").innerHTML = '<div class="empty"><p style="color:var(--green);font-size:1.1rem;font-weight:600;">All clear! No known vulnerabilities detected.</p></div>';
      var remCard = byId("remediationCard");
      if (remCard) remCard.classList.add("hidden");
      showResultView("vulns");
      return;
    }

    vulnResults.sort(function(a, b) {
      return getWorstSeverityIdx(a) - getWorstSeverityIdx(b);
    });
    renderVulnList(vulnResults, all);
    renderRemediation(vulnResults);
    showResultView("vulns");
  } catch (err) {
    console.error("renderResults error:", err);
    byId("scanError").classList.remove("hidden");
    byId("errorMsg").textContent = "Failed to render results: " + (err.message || String(err));
  }
}

/* ── History ── */
function loadHistory() {
  var loading = byId("historyLoading");
  var empty = byId("historyEmpty");
  var table = byId("historyTable");
  var tbody = byId("historyBody");

  if (loading) loading.classList.remove("hidden");
  if (empty) empty.classList.add("hidden");
  if (table) table.classList.add("hidden");

  fetch("/api/scans?limit=50")
  .then(function(res) { return res.json(); })
  .then(function(data) {
    var scans = data.scans || [];
    if (loading) loading.classList.add("hidden");
    if (scans.length === 0) {
      if (empty) empty.classList.remove("hidden");
      return;
    }
    if (table) table.classList.remove("hidden");
    var rows = "";
    var i;
    for (i = 0; i < scans.length; i++) {
      var s = scans[i];
      var dt = new Date(s.timestamp).toLocaleString();
      var rk = s.riskScore >= 60 ? "var(--red)" : s.riskScore >= 30 ? "var(--orange)" : "var(--green)";
      var tgt = s.target.split("/").pop() || s.target;
      rows += "<tr>";
      rows += "<td>" + esc(dt) + "</td>";
      rows += '<td title="' + esc(s.target) + '">' + esc(tgt) + "</td>";
      rows += "<td>" + s.totalDeps + "</td>";
      rows += "<td>" + (s.totalVulns > 0 ? '<span style="color:var(--red)">' + s.totalVulns + "</span>" : '<span style="color:var(--green)">0</span>') + "</td>";
      rows += '<td><span class="risk-badge" style="background:' + rk + '22;color:' + rk + '">' + Math.round(s.riskScore) + "</span></td>";
      rows += "<td><button class='btn btn-secondary' style='padding:4px 10px;font-size:0.8rem;' onclick='viewScan(&quot;" + esc(s.id) + "&quot;)'>View</button></td>";
      rows += "</tr>";
    }
    if (tbody) tbody.innerHTML = rows;
  })
  .catch(function(err) {
    if (loading) loading.classList.add("hidden");
    if (empty) {
      empty.classList.remove("hidden");
      var p = empty.querySelector("p");
      if (p) p.textContent = "Failed to load history: " + (err.message || String(err));
    }
  });
}
/* loadHistory is global */

function viewScan(id) {
  fetch("/api/scans/" + id)
  .then(function(res) { return res.json(); })
  .then(function(data) {
    if (data.error) throw new Error(data.error);
    currentReport = data;
    var allTabs = document.querySelectorAll(".tab");
    var ti;
    for (ti = 0; ti < allTabs.length; ti++) allTabs[ti].classList.remove("active");
    var scanTab = document.querySelector("[data-tab='scan']");
    if (scanTab) scanTab.classList.add("active");
    var tabScan = byId("tab-scan");
    var tabHistory = byId("tab-history");
    if (tabScan) tabScan.classList.remove("hidden");
    if (tabHistory) tabHistory.classList.add("hidden");
    renderResults(data);
  })
  .catch(function(err) {
    alert("Failed to load scan: " + (err.message || String(err)));
  });
}
/* viewScan is global */

/* ── Export ── */
function exportJSON() {
  if (!currentReport) return;
  downloadFile("scato-report.json", JSON.stringify(currentReport, null, 2), "application/json");
}
/* exportJSON is global */

function exportSBOM() {
  if (!currentReport) return;
  var comps = [];
  var all = currentReport.results || [];
  var i;
  for (i = 0; i < all.length; i++) {
    var r = all[i];
    comps.push({
      type: "library",
      name: r.dependency.name,
      version: r.dependency.version,
      purl: r.dependency.purl || "pkg:" + r.dependency.ecosystem + "/" + r.dependency.name + "@" + r.dependency.version
    });
  }
  var bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: currentReport.timestamp,
      tools: { components: [{ type: "application", name: "scato", version: "3.0.0" }] }
    },
    components: comps
  };
  downloadFile("scato-sbom.json", JSON.stringify(bom, null, 2), "application/json");
}
/* exportSBOM is global */

function downloadFile(name, content, mimeType) {
  var blob = new Blob([content], { type: mimeType });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Vulnerability detail modal ── */
function getVulnLinks(vuln) {
  var links = [];
  if (vuln.id.indexOf("CVE-") === 0) {
    links.push({ label: "View on NVD", url: "https://nvd.nist.gov/vuln/detail/" + vuln.id });
  }
  if (vuln.id.indexOf("GHSA-") === 0) {
    links.push({ label: "GitHub Advisory", url: "https://github.com/advisories/" + vuln.id });
  }
  links.push({ label: "OSV", url: "https://osv.dev/vulnerability/" + vuln.id });

  var aliases = vuln.aliases || [];
  var ai;
  for (ai = 0; ai < aliases.length; ai++) {
    if (aliases[ai].indexOf("CVE-") === 0) {
      var dup = false;
      var li;
      for (li = 0; li < links.length; li++) {
        if (links[li].url.indexOf(aliases[ai]) !== -1) { dup = true; break; }
      }
      if (!dup) links.push({ label: "NVD: " + aliases[ai], url: "https://nvd.nist.gov/vuln/detail/" + aliases[ai] });
    }
  }

  var refs = vuln.references || [];
  var ri;
  for (ri = 0; ri < Math.min(refs.length, 3); ri++) {
    if (refs[ri] && refs[ri].indexOf("http") === 0) {
      links.push({ label: "Reference " + (ri + 1), url: refs[ri] });
    }
  }
  return links;
}

function openVulnDetail(resultIdx, vulnIdx) {
  if (!currentReport || !currentReport.results) return;
  var result = currentReport.results[resultIdx];
  if (!result || !result.vulnerabilities || !result.vulnerabilities[vulnIdx]) return;
  var vuln = result.vulnerabilities[vulnIdx];
  var dep = result.dependency || {};

  byId("vulnModalTitle").textContent = (vuln.id || "Vulnerability") + " in " + (dep.name || "") + "@" + (dep.version || "");
  var links = getVulnLinks(vuln);
  var b = "";

  b += '<div class="vuln-detail-section"><h4>Summary</h4><p>' + esc(vuln.summary || "No summary available.") + "</p></div>";
  if (vuln.details) {
    b += '<div class="vuln-detail-section"><h4>Description</h4><p style="white-space:pre-wrap;">' + esc(vuln.details) + "</p></div>";
  }

  b += '<div class="vuln-detail-section"><h4>Severity &amp; scores</h4><p>';
  b += '<span class="badge badge-' + (vuln.severity || "unknown").toLowerCase() + '">' + (vuln.severity || "UNKNOWN") + "</span> ";
  if (vuln.isKnownExploited) b += '<span class="badge badge-kev">CISA KEV</span> ';
  if (vuln.score != null) b += " CVSS: " + vuln.score + (vuln.cvssVector ? " (" + esc(vuln.cvssVector) + ")" : "") + ".";
  if (vuln.epssScore != null) b += " EPSS: " + (vuln.epssScore * 100).toFixed(2) + "% probability of exploitation.";
  b += "</p></div>";

  b += '<div class="vuln-detail-section"><h4>Affected / fix</h4><p>';
  b += "Affected versions: " + esc(vuln.affected_versions || "unknown") + ".<br>";
  if (vuln.fixed_version) {
    b += "Fix: upgrade to <strong>" + esc(vuln.fixed_version) + "</strong>.";
  } else {
    b += "No fix version reported.";
  }
  b += "</p></div>";

  if (vuln.isKnownExploited && (vuln.kevDateAdded || vuln.kevDueDate)) {
    b += '<div class="vuln-detail-section"><h4>CISA KEV</h4><p>';
    if (vuln.kevDateAdded) b += "Added to KEV: " + esc(vuln.kevDateAdded) + ". ";
    if (vuln.kevDueDate) b += "Remediation due: <strong>" + esc(vuln.kevDueDate) + "</strong>.";
    b += "</p></div>";
  }

  if (vuln.cwes && vuln.cwes.length) {
    b += '<div class="vuln-detail-section"><h4>Weaknesses (CWE)</h4><p>';
    var cweLinks = [];
    var ci;
    for (ci = 0; ci < vuln.cwes.length; ci++) {
      var cid = vuln.cwes[ci].replace("CWE-", "");
      cweLinks.push('<a href="https://cwe.mitre.org/data/definitions/' + cid + '.html" target="_blank" rel="noopener">' + esc(vuln.cwes[ci]) + "</a>");
    }
    b += cweLinks.join(", ") + "</p></div>";
  }

  b += '<div class="vuln-detail-section"><h4>Dates</h4><p>Published: ' + esc(vuln.published || "unknown");
  if (vuln.modified) b += "; Modified: " + esc(vuln.modified);
  b += "</p></div>";

  b += '<div class="vuln-detail-section"><h4>External links</h4><div class="vuln-detail-links">';
  var lk;
  for (lk = 0; lk < links.length; lk++) {
    b += '<a href="' + esc(links[lk].url) + '" target="_blank" rel="noopener">' + esc(links[lk].label) + "</a>";
  }
  b += "</div></div>";

  byId("vulnModalBody").innerHTML = b;
  byId("vulnModal").classList.remove("hidden");
  document.body.style.overflow = "hidden";
}
/* openVulnDetail is global */

function closeVulnModal() {
  byId("vulnModal").classList.add("hidden");
  document.body.style.overflow = "";
}
/* closeVulnModal is global */

function findNodeInTree(nodes, name) {
  if (!nodes || !nodes.length) return null;
  for (var i = 0; i < nodes.length; i++) {
    if (nodes[i].dependency && nodes[i].dependency.name === name) return nodes[i];
    var found = findNodeInTree(nodes[i].children, name);
    if (found) return found;
  }
  return null;
}

function subtreeHtml(node, prefix, isLast) {
  if (!node) return "";
  var d = node.dependency;
  var NL = String.fromCharCode(10);
  var connector = isLast ? '\u2514\u2500\u2500 ' : '\u251C\u2500\u2500 ';
  var html = '<span class="mtree-connector">' + esc(prefix + connector) + '</span>';
  html += '<span class="mtree-name">' + esc(d.name) + '</span>';
  html += '<span class="mtree-ver">@' + esc(d.version) + '</span>' + NL;
  if (node.children && node.children.length > 0) {
    var childPrefix = prefix + (isLast ? '    ' : '\u2502   ');
    for (var j = 0; j < node.children.length; j++) {
      html += subtreeHtml(node.children[j], childPrefix, j === node.children.length - 1);
    }
  }
  return html;
}

function openDepDetail(name, version, ecosystem) {
  var modalEl = byId("depModal");
  var titleEl = byId("depModalTitle");
  var bodyEl = byId("depModalBody");
  if (!modalEl || !titleEl || !bodyEl) return;
  titleEl.textContent = (name || "") + "@" + (version || "") + " (" + (ecosystem || "") + ")";
  bodyEl.innerHTML = '<p class="muted">Loading...</p>';
  modalEl.classList.remove("hidden");
  document.body.style.overflow = "hidden";

  var treeNode = null;
  if (currentReport && currentReport.dependencyTrees) {
    for (var t = 0; t < currentReport.dependencyTrees.length; t++) {
      if (currentReport.dependencyTrees[t].ecosystem === ecosystem) {
        treeNode = findNodeInTree(currentReport.dependencyTrees[t].nodes, name);
        break;
      }
    }
  }

  function done(description, latestVersion) {
    var parts = [];
    if (description) parts.push("<p><strong>About</strong></p><p>" + esc(description) + "</p>");
    parts.push("<p><strong>Versions</strong></p><p>Current: " + esc(version || "—") + (latestVersion ? " &middot; Latest: " + esc(latestVersion) : "") + "</p>");
    parts.push("<p><strong>Dependency tree</strong></p>");
    if (treeNode && treeNode.children && treeNode.children.length > 0) {
      var sub = "";
      for (var k = 0; k < treeNode.children.length; k++) {
        sub += subtreeHtml(treeNode.children[k], '', k === treeNode.children.length - 1);
      }
      parts.push('<div class="dep-modal-tree">' + sub + '</div>');
    } else parts.push('<p class="muted">No sub-dependencies in this scan.</p>');
    bodyEl.innerHTML = parts.join("");
  }

  var base = (typeof window !== "undefined" && window.location && window.location.origin) ? window.location.origin : "";
  fetch(base + "/api/package-info?ecosystem=" + encodeURIComponent(ecosystem || "") + "&name=" + encodeURIComponent(name || ""))
    .then(function(r) { return r.json(); })
    .then(function(data) { done(data.description || "", data.latestVersion || ""); })
    .catch(function() { done("", ""); });
}
/* openDepDetail is global */

function openDepDetailFromEl(el) {
  if (!el) return;
  var name = el.getAttribute("data-dep-name");
  var version = el.getAttribute("data-dep-version");
  var ecosystem = el.getAttribute("data-dep-ecosystem");
  openDepDetail(name, version, ecosystem);
}
/* openDepDetailFromEl is global */

function closeDepModal() {
  var m = byId("depModal");
  if (m) m.classList.add("hidden");
  document.body.style.overflow = "";
}
/* closeDepModal is global */

function showResultView(which) {
  var vulnPanel = byId("vulnPanel");
  var depPanel = byId("depPanel");
  var btnVulns = byId("btnViewVulns");
  var btnDeps = byId("btnViewDeps");
  if (which === "deps") {
    if (depPanel) depPanel.classList.remove("hidden");
    if (vulnPanel) vulnPanel.classList.add("hidden");
    if (btnDeps) btnDeps.classList.add("active");
    if (btnVulns) btnVulns.classList.remove("active");
  } else {
    if (vulnPanel) vulnPanel.classList.remove("hidden");
    if (depPanel) depPanel.classList.add("hidden");
    if (btnVulns) btnVulns.classList.add("active");
    if (btnDeps) btnDeps.classList.remove("active");
  }
}
/* showResultView is global */

/* ── Init ── */
function initDashboard() {
  /* Tabs */
  var tabs = document.querySelectorAll(".tab");
  var ti;
  for (ti = 0; ti < tabs.length; ti++) {
    (function(tab) {
      tab.addEventListener("click", function() {
        var j;
        for (j = 0; j < tabs.length; j++) tabs[j].classList.remove("active");
        tab.classList.add("active");
        var tgt = tab.getAttribute("data-tab");
        var ts = byId("tab-scan");
        var th = byId("tab-history");
        if (ts) { if (tgt === "scan") ts.classList.remove("hidden"); else ts.classList.add("hidden"); }
        if (th) { if (tgt === "history") th.classList.remove("hidden"); else th.classList.add("hidden"); }
        if (tgt === "history") loadHistory();
      });
    })(tabs[ti]);
  }

  /* Scan button + Enter key */
  var scanBtn = byId("scanBtn");
  var targetIn = byId("targetInput");
  if (scanBtn) scanBtn.addEventListener("click", function() { runScan(); });
  if (targetIn) targetIn.addEventListener("keydown", function(e) { if (e.key === "Enter") runScan(); });

  /* Dep panel: click dependency (list or tree label) to open detail modal, or toggle tree node */
  var depOverview = byId("depOverview");
  if (depOverview) {
    depOverview.addEventListener("click", function(e) {
      /* Tree toggle button */
      var toggleBtn = e.target.closest ? e.target.closest(".dep-tree-toggle-btn") : null;
      if (toggleBtn) { toggleTreeNode(toggleBtn); return; }
      /* Dependency click (list rows or tree package names) */
      var el = e.target.closest ? e.target.closest(".dep-node-clickable, .dep-child-clickable, .dep-tree-pkg") : null;
      if (!el) return;
      var name = el.getAttribute("data-dep-name");
      var version = el.getAttribute("data-dep-version");
      var ecosystem = el.getAttribute("data-dep-ecosystem");
      if (name != null) openDepDetail(name, version || "", ecosystem || "");
    });
  }

  /* Vuln row click delegation */
  var rl = byId("resultsList");
  if (rl) {
    rl.addEventListener("click", function(e) {
      var item = e.target;
      while (item && item !== rl) {
        if (item.classList && item.classList.contains("vuln-item-clickable")) {
          var rIdx = item.getAttribute("data-result-idx");
          var vIdx = item.getAttribute("data-vuln-idx");
          if (rIdx != null && vIdx != null) openVulnDetail(parseInt(rIdx, 10), parseInt(vIdx, 10));
          return;
        }
        item = item.parentNode;
      }
    });
    rl.addEventListener("keydown", function(e) {
      if (e.key !== "Enter") return;
      var item = e.target;
      while (item && item !== rl) {
        if (item.classList && item.classList.contains("vuln-item-clickable")) {
          e.preventDefault();
          var rIdx = item.getAttribute("data-result-idx");
          var vIdx = item.getAttribute("data-vuln-idx");
          if (rIdx != null && vIdx != null) openVulnDetail(parseInt(rIdx, 10), parseInt(vIdx, 10));
          return;
        }
        item = item.parentNode;
      }
    });
  }

  /* Vuln modal close on backdrop + Escape */
  var modal = byId("vulnModal");
  if (modal) {
    modal.addEventListener("click", function(e) {
      if (e.target === modal) closeVulnModal();
    });
    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape" && !modal.classList.contains("hidden")) closeVulnModal();
    });
  }
  /* Dep modal close on backdrop + Escape */
  var depModal = byId("depModal");
  if (depModal) {
    depModal.addEventListener("click", function(e) {
      if (e.target === depModal) closeDepModal();
    });
    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape" && depModal && !depModal.classList.contains("hidden")) closeDepModal();
    });
  }
}

/* ── Boot ── */
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initDashboard);
} else {
  initDashboard();
}

</script>
</body>
</html>`;
}

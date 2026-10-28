(() => {
  "use strict";

  const elements = {
    modeTabs: Array.from(document.querySelectorAll(".mode-tab")),
    repositoryForm: document.getElementById("repository-form"),
    codeForm: document.getElementById("code-form"),
    repositoryInput: document.getElementById("repository-url"),
    branchInput: document.getElementById("branch-name"),
    codeInput: document.getElementById("code-input"),
    filenameInput: document.getElementById("code-filename"),
    repositoryButton: document.getElementById("scan-repository-button"),
    codeButton: document.getElementById("scan-code-button"),
    empty: document.getElementById("empty-state"),
    progress: document.getElementById("scan-progress"),
    progressPhase: document.getElementById("progress-phase"),
    progressDetail: document.getElementById("progress-detail"),
    progressCount: document.getElementById("progress-count"),
    progressTrack: document.querySelector(".progress-track"),
    progressFill: document.getElementById("progress-fill"),
    error: document.getElementById("error-state"),
    errorMessage: document.getElementById("error-message"),
    retry: document.getElementById("retry-button"),
    results: document.getElementById("scan-results"),
    export: document.getElementById("export-button"),
    clear: document.getElementById("clear-button"),
    source: document.getElementById("report-source"),
    branch: document.getElementById("report-branch"),
    riskPanel: document.getElementById("risk-panel"),
    riskPill: document.getElementById("risk-pill"),
    riskScore: document.getElementById("risk-score"),
    riskFill: document.getElementById("risk-meter-fill"),
    riskNote: document.getElementById("risk-note"),
    metricFindings: document.getElementById("metric-findings"),
    metricFiles: document.getElementById("metric-files"),
    metricSkipped: document.getElementById("metric-skipped"),
    severitySummary: document.getElementById("severity-summary"),
    findingsSubtitle: document.getElementById("findings-subtitle"),
    search: document.getElementById("finding-search"),
    findingsList: document.getElementById("findings-list"),
    findingsEmpty: document.getElementById("findings-empty"),
    inventory: document.getElementById("file-inventory"),
    inventoryCount: document.getElementById("inventory-count"),
    inventoryList: document.getElementById("inventory-list"),
    warnings: document.getElementById("warnings-list"),
  };

  let currentMode = "repository";
  let currentReport = null;
  let lastRequest = null;
  let selectedSeverity = "all";
  let searchTerm = "";

  function setMode(mode) {
    currentMode = mode;
    const repositorySelected = mode === "repository";
    elements.repositoryForm.hidden = !repositorySelected;
    elements.codeForm.hidden = repositorySelected;
    elements.modeTabs.forEach((tab) => {
      const selected = tab.dataset.mode === mode;
      tab.classList.toggle("is-selected", selected);
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
  }

  setMode(currentMode);

  elements.modeTabs.forEach((tab) => {
    tab.addEventListener("click", () => setMode(tab.dataset.mode));
  });

  function showProgress() {
    elements.empty.hidden = true;
    elements.error.hidden = true;
    elements.results.hidden = true;
    elements.progress.hidden = false;
    elements.export.hidden = true;
    elements.clear.hidden = true;
    updateProgress({ phase: "Preparing scan…", current: 0, total: 0 });
  }

  function setMeter(element, percent) {
    const rounded = Math.max(0, Math.min(100, Math.round(percent / 5) * 5));
    for (const name of Array.from(element.classList)) {
      if (/^meter-\d+$/.test(name)) element.classList.remove(name);
    }
    element.classList.add(`meter-${rounded}`);
  }

  function updateProgress(progress) {
    const phase = typeof progress.phase === "string" ? progress.phase : "Scanning…";
    const current = Number.isFinite(progress.current) ? progress.current : 0;
    const total = Number.isFinite(progress.total) ? progress.total : 0;
    elements.progressPhase.textContent = phase;

    if (progress.path) {
      elements.progressDetail.textContent = `Inspecting ${progress.path}`;
    } else if (phase.toLowerCase().includes("archive")) {
      elements.progressDetail.textContent = "Downloading a bounded public source archive";
    } else if (phase.toLowerCase().includes("tree")) {
      elements.progressDetail.textContent = "Reading file names and sizes from GitHub";
    } else if (phase.toLowerCase().includes("repository")) {
      elements.progressDetail.textContent = "Validating a public GitHub repository";
    } else if (phase.toLowerCase().includes("pasted")) {
      elements.progressDetail.textContent = "Checking the text in memory";
    } else {
      elements.progressDetail.textContent = "No source code is being executed";
    }

    let percent = 7;
    if (total > 0) {
      percent = Math.min(94, 20 + Math.round((current / total) * 72));
      elements.progressCount.textContent = `${current} of ${total} files processed`;
    } else if (phase.toLowerCase().includes("repository")) {
      percent = 8;
      elements.progressCount.textContent = "Validating repository";
    } else if (phase.toLowerCase().includes("archive")) {
      percent = 17;
      elements.progressCount.textContent = "Downloading source archive";
    } else if (phase.toLowerCase().includes("tree")) {
      percent = 20;
      elements.progressCount.textContent = "Loading repository tree";
    } else {
      elements.progressCount.textContent = "Preparing files";
    }
    setMeter(elements.progressFill, percent);
    elements.progressTrack.setAttribute("aria-valuenow", String(percent));
  }

  function setBusy(isBusy) {
    elements.repositoryButton.disabled = isBusy;
    elements.codeButton.disabled = isBusy;
    elements.repositoryButton.querySelector(".button-label").textContent = isBusy ? "Scanning…" : "Scan repository";
    elements.codeButton.querySelector(".button-label").textContent = isBusy ? "Scanning…" : "Scan pasted code";
  }

  function showError(message) {
    elements.progress.hidden = true;
    elements.results.hidden = true;
    elements.empty.hidden = true;
    elements.error.hidden = false;
    elements.errorMessage.textContent = message || "An unexpected error occurred. Please try again.";
    elements.export.hidden = true;
    elements.clear.hidden = false;
  }

  function parseSseBlock(block) {
    let eventName = "message";
    const dataLines = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("event:")) eventName = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
    }
    if (!dataLines.length) return null;
    try {
      return { eventName, data: JSON.parse(dataLines.join("\n")) };
    } catch (_) {
      throw new Error("The scanner returned an unreadable response.");
    }
  }

  async function consumeScan(endpoint, payload) {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "text/event-stream" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      let message = `Request failed (HTTP ${response.status}).`;
      try {
        const body = await response.json();
        if (body && typeof body.error === "string") message = body.error;
      } catch (_) { /* keep fallback */ }
      throw new Error(message);
    }
    if (!response.body) throw new Error("Streaming responses are not supported by this browser.");

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let report = null;

    const handleBlock = (block) => {
      const event = parseSseBlock(block);
      if (!event) return;
      if (event.eventName === "progress") updateProgress(event.data);
      else if (event.eventName === "result") report = event.data;
      else if (event.eventName === "error") {
        throw new Error(event.data && event.data.message ? event.data.message : "The scan could not be completed.");
      }
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.search(/\r?\n\r?\n/);
      while (boundary !== -1) {
        const block = buffer.slice(0, boundary);
        const delimiterLength = buffer.slice(boundary).startsWith("\r\n\r\n") ? 4 : 2;
        buffer = buffer.slice(boundary + delimiterLength);
        handleBlock(block);
        boundary = buffer.search(/\r?\n\r?\n/);
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) handleBlock(buffer);
    if (!report) throw new Error("The connection ended before a scan report was received.");
    return report;
  }

  async function startScan(endpoint, payload) {
    lastRequest = { endpoint, payload };
    currentReport = null;
    selectedSeverity = "all";
    searchTerm = "";
    elements.search.value = "";
    showProgress();
    setBusy(true);
    document.getElementById("results-heading").scrollIntoView({ behavior: "smooth", block: "center" });

    try {
      const report = await consumeScan(endpoint, payload);
      renderReport(report);
    } catch (error) {
      showError(error instanceof Error ? error.message : "The scan could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  elements.repositoryForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const repository = elements.repositoryInput.value.trim();
    const branch = elements.branchInput.value.trim();
    startScan("/api/scan/repository", { repository, branch });
  });

  elements.codeForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const code = elements.codeInput.value;
    const filename = elements.filenameInput.value.trim() || "pasted-snippet.txt";
    startScan("/api/scan/code", { code, filename });
  });

  elements.retry.addEventListener("click", () => {
    if (lastRequest) startScan(lastRequest.endpoint, lastRequest.payload);
  });

  function safeSeverity(value) {
    return ["critical", "high", "medium", "low"].includes(value) ? value : "low";
  }

  function renderReport(report) {
    currentReport = report;
    elements.progress.hidden = true;
    elements.error.hidden = true;
    elements.empty.hidden = true;
    elements.results.hidden = false;
    elements.export.hidden = false;
    elements.clear.hidden = false;

    const isRepository = report.scan_type === "repository" && report.repository;
    const sourceName = isRepository ? (report.repository.full_name || "GitHub repository") : ((report.scanned_files?.[0]) || report.findings?.[0]?.path || elements.filenameInput.value.trim() || "pasted-snippet.txt");
    elements.source.textContent = sourceName;
    elements.branch.textContent = isRepository ? `Branch: ${report.repository.branch || "default"}` : "Pasted text · analyzed in memory";

    const summary = report.summary || {};
    const score = Math.max(0, Math.min(100, Number(summary.risk_score) || 0));
    const label = typeof summary.risk_label === "string" ? summary.risk_label : "No indicators";
    elements.riskScore.textContent = String(score);
    elements.riskPill.textContent = label;
    elements.riskPill.className = `risk-pill risk-${label.toLowerCase().replace(/\s+/g, "-")}`;
    setMeter(elements.riskFill, score);
    elements.riskNote.textContent = score === 0
      ? "No rule-based indicators matched. This is not proof of safety."
      : "Indicators need human review; a pattern match is not a malware verdict.";
    elements.metricFindings.textContent = String(Number(summary.findings) || 0);
    elements.metricFiles.textContent = String(Number(summary.files_scanned) || 0);
    elements.metricSkipped.textContent = String(Number(summary.files_skipped) || 0);

    const findings = Array.isArray(report.findings) ? report.findings : [];
    const severityCounts = summary.by_severity || {};
    renderSeverityFilters(severityCounts);
    elements.findingsSubtitle.textContent = findings.length === 1 ? "1 indicator · review it in context" : `${findings.length} indicators · review them in context`;
    renderFindings();
    renderInventory(report.scanned_files);
    renderWarnings(report.warnings);
  }

  function renderSeverityFilters(counts) {
    const options = [
      ["all", "All", Number(currentReport?.summary?.findings) || 0],
      ["critical", "Critical", Number(counts.critical) || 0],
      ["high", "High", Number(counts.high) || 0],
      ["medium", "Medium", Number(counts.medium) || 0],
      ["low", "Low", Number(counts.low) || 0],
    ];
    elements.severitySummary.replaceChildren();
    options.forEach(([value, label, count]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `filter-chip${selectedSeverity === value ? " is-selected" : ""}`;
      button.setAttribute("aria-pressed", String(selectedSeverity === value));
      const labelSpan = document.createElement("span");
      labelSpan.textContent = label;
      const countStrong = document.createElement("strong");
      countStrong.textContent = String(count);
      button.append(labelSpan, countStrong);
      button.addEventListener("click", () => {
        selectedSeverity = value;
        renderSeverityFilters(currentReport?.summary?.by_severity || {});
        renderFindings();
      });
      elements.severitySummary.append(button);
    });
  }

  function createFindingCard(finding) {
    const severity = safeSeverity(finding.severity);
    const card = document.createElement("details");
    card.className = `finding-card severity-${severity}`;

    const summary = document.createElement("summary");
    const badge = document.createElement("span");
    badge.className = `severity-tag severity-${severity}`;
    badge.textContent = severity;
    const title = document.createElement("span");
    title.className = "finding-title";
    title.textContent = finding.title || "Suspicious indicator";
    const location = document.createElement("span");
    location.className = "finding-location";
    const path = document.createElement("span");
    path.textContent = finding.path || "unknown file";
    path.title = finding.path || "";
    location.append(path);
    if (Number.isFinite(Number(finding.line))) {
      const line = document.createElement("em");
      line.textContent = `:${finding.line}`;
      location.append(line);
    }
    summary.append(badge, title, location);

    const detail = document.createElement("div");
    detail.className = "finding-detail";
    const category = document.createElement("p");
    const categoryLabel = document.createElement("strong");
    categoryLabel.textContent = `${finding.category || "Indicator"}: `;
    category.append(categoryLabel, document.createTextNode(finding.summary || "Review this match in context."));
    const recommendation = document.createElement("p");
    const recommendationLabel = document.createElement("strong");
    recommendationLabel.textContent = "Suggested review: ";
    recommendation.append(recommendationLabel, document.createTextNode(finding.recommendation || "Do not run untrusted code; verify its source and behavior."));
    detail.append(category, recommendation);
    if (finding.evidence) {
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      code.textContent = finding.evidence;
      pre.append(code);
      detail.append(pre);
    }

    card.append(summary, detail);
    return card;
  }

  function renderFindings() {
    const findings = Array.isArray(currentReport?.findings) ? currentReport.findings : [];
    const filtered = findings.filter((finding) => {
      if (selectedSeverity !== "all" && finding.severity !== selectedSeverity) return false;
      if (!searchTerm) return true;
      const haystack = [finding.title, finding.category, finding.path, finding.summary, finding.evidence]
        .filter(Boolean).join(" ").toLowerCase();
      return haystack.includes(searchTerm);
    });
    elements.findingsList.replaceChildren(...filtered.map(createFindingCard));
    elements.findingsEmpty.hidden = filtered.length !== 0;
    elements.findingsList.hidden = filtered.length === 0;
  }

  elements.search.addEventListener("input", () => {
    searchTerm = elements.search.value.trim().toLowerCase();
    renderFindings();
  });

  function renderInventory(files) {
    if (!Array.isArray(files) || files.length === 0) {
      elements.inventory.hidden = true;
      elements.inventoryList.replaceChildren();
      return;
    }
    elements.inventory.hidden = false;
    elements.inventoryCount.textContent = String(files.length);
    elements.inventoryList.replaceChildren();
    files.forEach((filename) => {
      const item = document.createElement("li");
      item.textContent = filename;
      item.title = filename;
      elements.inventoryList.append(item);
    });
  }

  function renderWarnings(warnings) {
    elements.warnings.replaceChildren();
    if (!Array.isArray(warnings)) return;
    warnings.forEach((warningText) => {
      if (typeof warningText !== "string") return;
      const item = document.createElement("div");
      item.className = "warning-item";
      const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      icon.setAttribute("viewBox", "0 0 18 18");
      icon.setAttribute("aria-hidden", "true");
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", "M9 2.3 16.2 15H1.8L9 2.3Zm0 4.2v4m0 2.1v.1");
      icon.append(path);
      const text = document.createElement("span");
      text.textContent = warningText;
      item.append(icon, text);
      elements.warnings.append(item);
    });
  }

  elements.export.addEventListener("click", () => {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    const base = (currentReport.repository?.full_name || "scan-report").replace(/[^A-Za-z0-9._-]+/g, "-");
    anchor.href = objectUrl;
    anchor.download = `${base}-scan-report.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
  });

  function clearResults() {
    currentReport = null;
    lastRequest = null;
    elements.progress.hidden = true;
    elements.error.hidden = true;
    elements.results.hidden = true;
    elements.empty.hidden = false;
    elements.export.hidden = true;
    elements.clear.hidden = true;
    elements.findingsList.replaceChildren();
    elements.warnings.replaceChildren();
    elements.search.value = "";
    selectedSeverity = "all";
    searchTerm = "";
  }

  elements.clear.addEventListener("click", clearResults);
})();

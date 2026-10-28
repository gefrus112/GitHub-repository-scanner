(() => {
  "use strict";

  const elements = {
    modeTabs: Array.from(document.querySelectorAll(".mode-tab")),
    repositoryForm: document.getElementById("repository-form"),
    fileForm: document.getElementById("file-form"),
    codeForm: document.getElementById("code-form"),
    vmPanel: document.getElementById("vm-panel"),
    scannerLayout: document.querySelector(".scanner-layout"),
    resultsCard: document.querySelector(".results-card"),
    scanCardHeading: document.getElementById("scan-card-heading"),
    scanCardDescription: document.getElementById("scan-card-description"),
    repositoryInput: document.getElementById("repository-url"),
    branchInput: document.getElementById("branch-name"),
    fileInput: document.getElementById("upload-file"),
    uploadDropzone: document.getElementById("upload-dropzone"),
    uploadTitle: document.getElementById("upload-title"),
    uploadSubtitle: document.getElementById("upload-subtitle"),
    codeInput: document.getElementById("code-input"),
    filenameInput: document.getElementById("code-filename"),
    repositoryButton: document.getElementById("scan-repository-button"),
    fileButton: document.getElementById("scan-file-button"),
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
    fileHash: document.getElementById("report-file-hash"),
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

  const GITHUB_API = "https://api.github.com";
  const SEVERITY_WEIGHT = { critical: 45, high: 30, medium: 15, low: 5 };
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  let currentMode = "repository";
  let currentReport = null;
  let lastRequest = null;
  let selectedFile = null;
  let selectedSeverity = "all";
  let searchTerm = "";
  let ruleSetPromise = null;

  function setMode(mode) {
    currentMode = mode;
    const isVmMode = mode === "vm";
    elements.repositoryForm.hidden = mode !== "repository";
    elements.fileForm.hidden = mode !== "file";
    elements.codeForm.hidden = mode !== "code";
    elements.vmPanel.hidden = !isVmMode;
    elements.resultsCard.hidden = isVmMode;
    elements.scannerLayout.classList.toggle("is-vm-mode", isVmMode);
    elements.scanCardHeading.textContent = isVmMode ? "Windows 11 VM setup" : "Start a scan";
    elements.scanCardDescription.textContent = isVmMode ? "Use your own laptop; no cloud provider." : "Choose where the code lives.";
    elements.modeTabs.forEach((tab) => {
      const selected = tab.dataset.mode === mode;
      tab.classList.toggle("is-selected", selected);
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
  }

  setMode(currentMode);
  elements.modeTabs.forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));

  async function loadRuleSet() {
    if (!ruleSetPromise) {
      const rulesUrl = new URL("rules.json", document.baseURI);
      ruleSetPromise = fetch(rulesUrl, { headers: { Accept: "application/json" } })
        .then(async (response) => {
          if (!response.ok) throw new Error(`Could not load the scanner rules (HTTP ${response.status}).`);
          const config = await response.json();
          if (!config || !Array.isArray(config.rules) || !config.suspiciousFilenamePattern) {
            throw new Error("The scanner rules file is invalid.");
          }
          config.compiledRules = config.rules.map((rule) => ({
            ...rule,
            regex: new RegExp(rule.pattern, rule.flags || "i"),
          }));
          config.filenameRegex = new RegExp(config.suspiciousFilenamePattern, "i");
          return config;
        })
        .catch((error) => {
          ruleSetPromise = null;
          throw error;
        });
    }
    return ruleSetPromise;
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
    const findings = Number.isFinite(progress.findings) ? progress.findings : null;
    elements.progressPhase.textContent = phase;

    if (progress.path) {
      elements.progressDetail.textContent = `Inspecting ${progress.path}${findings === null ? "" : ` · ${findings} indicator${findings === 1 ? "" : "s"} so far`}`;
    } else if (phase.toLowerCase().includes("archive")) {
      elements.progressDetail.textContent = "Reading public source files directly from GitHub";
    } else if (phase.toLowerCase().includes("tree")) {
      elements.progressDetail.textContent = "Listing supported files in the repository";
    } else if (phase.toLowerCase().includes("repository")) {
      elements.progressDetail.textContent = "Validating the public GitHub repository";
    } else if (phase.toLowerCase().includes("file locally") || phase.toLowerCase().includes("file text locally")) {
      elements.progressDetail.textContent = "Reading the selected file in this browser tab";
    } else if (phase.toLowerCase().includes("pasted")) {
      elements.progressDetail.textContent = "Checking text locally in this browser tab";
    } else {
      elements.progressDetail.textContent = "No source code is being executed";
    }

    let percent = 7;
    if (total > 0) {
      percent = Math.min(94, 20 + Math.round((current / total) * 72));
      elements.progressCount.textContent = `${current} of ${total} files inspected`;
    } else if (phase.toLowerCase().includes("repository")) {
      percent = 8;
      elements.progressCount.textContent = "Validating repository";
    } else if (phase.toLowerCase().includes("archive")) {
      percent = 17;
      elements.progressCount.textContent = "Reading repository metadata";
    } else if (phase.toLowerCase().includes("tree")) {
      percent = 20;
      elements.progressCount.textContent = "Listing repository files";
    } else if (phase.toLowerCase().includes("file locally") || phase.toLowerCase().includes("file text locally")) {
      percent = 30;
      elements.progressCount.textContent = "Reading file locally";
    } else {
      elements.progressCount.textContent = "Preparing local scan";
    }
    setMeter(elements.progressFill, percent);
    elements.progressTrack.setAttribute("aria-valuenow", String(percent));
  }

  function showProgress() {
    elements.empty.hidden = true;
    elements.error.hidden = true;
    elements.results.hidden = true;
    elements.progress.hidden = false;
    elements.export.hidden = true;
    elements.clear.hidden = true;
    updateProgress({ phase: "Preparing scan…", current: 0, total: 0 });
  }

  function setBusy(isBusy) {
    elements.repositoryButton.disabled = isBusy;
    elements.fileButton.disabled = isBusy || !selectedFile;
    elements.codeButton.disabled = isBusy;
    elements.repositoryButton.querySelector(".button-label").textContent = isBusy ? "Scanning…" : "Scan repository";
    elements.fileButton.querySelector(".button-label").textContent = isBusy ? "Scanning…" : "Scan selected file";
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

  function redactEvidence(text) {
    return text
      .replace(/(https?:\/\/(?:(?:canary|ptb)\.)?discord(?:app)?\.com\/api\/webhooks\/)[^\s"'<>]+/ig, "$1[REDACTED]")
      .replace(/(https?:\/\/api\.telegram\.org\/bot)[^/\s"'<>]+/ig, "$1[REDACTED]")
      .replace(/\bgh[pousr]_[A-Za-z0-9_]{10,}\b/g, "[REDACTED_TOKEN]")
      .replace(/(\b(?:bearer|authorization)\s*[:= ]\s*)[A-Za-z0-9._~+\/-]{12,}=*/ig, "$1[REDACTED]")
      .replace(/(\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|webhook[_-]?token|github[_-]?token|token|secret|password|private[_-]?key)\b\s*[:=]\s*["']?)[^\s"'`,;]{8,}/ig, "$1[REDACTED]")
      .trim()
      .slice(0, 239);
  }

  function suspiciousFilenameFinding(path, rules) {
    const basename = String(path).replace(/\\/g, "/").split("/").pop();
    if (!rules.filenameRegex.test(basename)) return null;
    return {
      id: "suspicious-filename",
      title: "Suspicious filename keyword",
      severity: "low",
      category: "File metadata",
      path,
      line: 1,
      evidence: redactEvidence(`Filename: ${basename}`),
      summary: "The filename contains a term often associated with malware. A name alone is a weak signal, not proof of malicious behavior.",
      behavior: "A filename has no execution behavior by itself; this match only indicates a word worth reviewing.",
      install_effect: "No effect can be inferred from a filename. Inspect the file before opening or installing it.",
      recommendation: "Review the file contents and provenance; do not judge safety by filename alone.",
    };
  }

  function analyzeText(text, path, rules) {
    const findings = [];
    const limitedText = text.slice(0, rules.maxCodeChars);
    const lines = limitedText.split(/\r?\n/);
    for (let index = 0; index < lines.length && findings.length < 250; index += 1) {
      const line = lines[index];
      for (const rule of rules.compiledRules) {
        if (rule.regex.test(line)) {
          findings.push({
            id: rule.id,
            title: rule.title,
            severity: rule.severity,
            category: rule.category,
            path,
            line: index + 1,
            evidence: redactEvidence(line),
            summary: rule.summary,
            behavior: rule.behavior,
            install_effect: rule.install_effect,
            recommendation: rule.recommendation,
          });
          if (findings.length >= 250) break;
        }
      }
    }
    if (findings.length < 250) {
      const nameFinding = suspiciousFilenameFinding(path, rules);
      if (nameFinding) findings.push(nameFinding);
    }
    return findings;
  }

  function summarize(findings) {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const uniqueRules = new Map();
    findings.forEach((finding) => {
      if (Object.prototype.hasOwnProperty.call(bySeverity, finding.severity)) bySeverity[finding.severity] += 1;
      uniqueRules.set(finding.id, finding.severity);
    });
    const score = Math.min(100, Array.from(uniqueRules.values()).reduce((sum, severity) => sum + (SEVERITY_WEIGHT[severity] || 0), 0));
    let label = "No indicators";
    if (score >= 70) label = "Critical";
    else if (score >= 45) label = "High";
    else if (score >= 20) label = "Elevated";
    else if (score > 0) label = "Guarded";
    return { risk_score: score, risk_label: label, findings: findings.length, by_severity: bySeverity };
  }

  function createTextReport(scanType, filename, text, rules, specificWarning) {
    if (!text.trim()) throw new Error("The selected text is empty. Add text and scan again.");
    if (text.length > rules.maxCodeChars) throw new Error(`Text exceeds the ${Number(rules.maxCodeChars).toLocaleString()}-character scan limit.`);
    const findings = analyzeText(text, filename, rules);
    return {
      scan_type: scanType,
      scan_state: "complete",
      filename,
      repository: null,
      summary: { ...summarize(findings), files_scanned: 1, files_skipped: 0 },
      findings,
      scanned_files: [filename],
      warnings: [
        "Heuristic static analysis only: findings are review leads, not proof of malware; no findings do not prove safety.",
        specificWarning,
      ],
    };
  }

  function parseGitHubInput(rawInput, branchOverride) {
    let value = rawInput.trim();
    if (!value) throw new Error("Enter a GitHub repository URL.");
    if (value.length > 2048) throw new Error("Repository URL is too long.");
    if (/^github\.com\//i.test(value)) value = `https://${value}`;

    let segments;
    let parsedBranch = null;
    if (value.includes("://")) {
      let parsed;
      try { parsed = new URL(value); } catch (_) { throw new Error("That repository URL is invalid."); }
      if (parsed.protocol !== "https:" || !["github.com", "www.github.com"].includes(parsed.hostname.toLowerCase())) {
        throw new Error("For safety, use a public repository link from https://github.com.");
      }
      if (parsed.username || parsed.password || (parsed.port && parsed.port !== "443")) {
        throw new Error("That GitHub URL contains unsupported credentials or a port.");
      }
      try { segments = parsed.pathname.split("/").filter(Boolean).map(decodeURIComponent); }
      catch (_) { throw new Error("That GitHub URL contains invalid path encoding."); }
    } else {
      segments = value.split("/").filter(Boolean);
    }
    if (segments.length < 2) throw new Error("Use https://github.com/owner/repository.");
    const owner = segments[0];
    let repo = segments[1];
    if (repo.toLowerCase().endsWith(".git")) repo = repo.slice(0, -4);
    if (!/^[A-Za-z0-9_.-]{1,100}$/.test(owner) || owner === "." || owner === "..") throw new Error("The repository owner is invalid.");
    if (!/^[A-Za-z0-9_.-]{1,100}$/.test(repo) || repo === "." || repo === "..") throw new Error("The repository name is invalid.");
    if (segments.length > 2) {
      if (segments.length >= 4 && ["tree", "blob"].includes(segments[2])) parsedBranch = segments[3];
      else throw new Error("Paste a repository root, /tree/branch, or /blob/branch link.");
    }
    const branch = branchOverride.trim() || parsedBranch;
    if (branch) {
      if (branch.length > 200 || /[\x00-\x1f]/.test(branch) || branch.startsWith("-")) throw new Error("The branch name is invalid.");
      if (branch.split("/").some((part) => !part || part === "." || part === "..")) throw new Error("The branch name contains an unsupported path segment.");
    }
    return { owner, repo, branch };
  }

  async function githubJson(path) {
    let response;
    try {
      response = await fetch(`${GITHUB_API}${path}`, { headers: { Accept: "application/vnd.github+json" } });
    } catch (_) {
      throw new Error("The browser could not reach GitHub's public API. Check your connection or try again later.");
    }
    if (response.status === 403) {
      const remaining = response.headers.get("X-RateLimit-Remaining");
      if (remaining === "0") throw new Error("GitHub's unauthenticated API limit was reached. Wait for it to reset before scanning again.");
      throw new Error("GitHub declined the request. Check that the repository is public and try again later.");
    }
    if (response.status === 404) throw new Error("Repository, branch, or file not found. Private repositories are not supported.");
    if (!response.ok) throw new Error(`GitHub's API returned HTTP ${response.status}.`);
    try { return await response.json(); }
    catch (_) { throw new Error("GitHub returned an unreadable API response."); }
  }

  function increment(counts, key, by = 1) {
    counts[key] = (counts[key] || 0) + by;
  }

  function pathIsSuspicious(path, rules) {
    return rules.filenameRegex.test(path.split("/").pop());
  }

  function candidatePriority(entry, rules) {
    const path = entry.path;
    const name = path.split("/").pop().toLowerCase();
    const suffix = name.includes(".") ? name.slice(name.lastIndexOf(".")) : "";
    let priority = rules.scriptSuffixes.includes(suffix) || ["dockerfile", "makefile", ".env"].includes(name) ? 1 : 2;
    if (pathIsSuspicious(path, rules)) priority = 0;
    return [priority, path.length, path.toLowerCase()];
  }

  function repositoryCandidates(tree, rules) {
    const counts = {};
    const candidates = [];
    const ignored = new Set(rules.ignoredDirectoryNames.map((item) => item.toLowerCase()));
    const extensions = new Set(rules.scannableSuffixes.map((item) => item.toLowerCase()));
    const basenames = new Set(rules.scannableBasenames.map((item) => item.toLowerCase()));
    const excludedNames = new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "cargo.lock", "composer.lock"]);

    tree.forEach((entry) => {
      if (!entry || entry.type !== "blob" || typeof entry.path !== "string") return;
      const parts = entry.path.split("/");
      if (entry.path.startsWith("/") || parts.some((part) => part === ".." || part === "." || part === "")) {
        increment(counts, "unsafe_paths");
        return;
      }
      if (parts.slice(0, -1).some((part) => ignored.has(part.toLowerCase()))) {
        increment(counts, "ignored_folders");
        return;
      }
      const name = parts[parts.length - 1].toLowerCase();
      const dot = name.lastIndexOf(".");
      const suffix = dot > 0 ? name.slice(dot) : "";
      if (!extensions.has(suffix) && !basenames.has(name) && !pathIsSuspicious(entry.path, rules)) {
        increment(counts, "unsupported_files");
        return;
      }
      if (name.endsWith(".min.js") || excludedNames.has(name)) {
        increment(counts, "generated_or_lockfiles");
        return;
      }
      if (!Number.isInteger(entry.size) || entry.size < 0 || entry.size > rules.maxFileBytes) {
        increment(counts, "oversize_files");
        return;
      }
      candidates.push(entry);
    });

    candidates.sort((a, b) => {
      const aa = candidatePriority(a, rules);
      const bb = candidatePriority(b, rules);
      return aa[0] - bb[0] || aa[1] - bb[1] || aa[2].localeCompare(bb[2]);
    });
    if (candidates.length > rules.maxFiles) {
      increment(counts, "scan_limit", candidates.length - rules.maxFiles);
      candidates.length = rules.maxFiles;
    }
    return { candidates, counts };
  }

  function decodeBlob(base64Content) {
    const compact = base64Content.replace(/\s/g, "");
    let binary;
    try { binary = atob(compact); }
    catch (_) { return { error: "unreadable" }; }
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    if (bytes.includes(0)) return { error: "binary" };
    try {
      return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes), byteLength: bytes.length };
    } catch (_) {
      return { error: "unreadable" };
    }
  }

  function sortFindings(findings) {
    findings.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
      || a.path.toLowerCase().localeCompare(b.path.toLowerCase())
      || a.line - b.line
      || a.id.localeCompare(b.id));
    if (findings.length > 250) findings.length = 250;
    return findings;
  }

  async function scanRepository(request, rules) {
    const parsed = parseGitHubInput(request.repository, request.branch);
    const ownerPath = encodeURIComponent(parsed.owner);
    const repoPath = encodeURIComponent(parsed.repo);
    updateProgress({ phase: "Loading repository details", current: 0, total: 0 });
    const metadata = await githubJson(`/repos/${ownerPath}/${repoPath}`);
    if (!metadata || !metadata.default_branch) throw new Error("GitHub did not return a default branch for this repository.");
    const branch = parsed.branch || metadata.default_branch;

    updateProgress({ phase: `Loading the ${branch} branch tree`, current: 0, total: 0 });
    const treeResponse = await githubJson(`/repos/${ownerPath}/${repoPath}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
    if (!treeResponse || !Array.isArray(treeResponse.tree)) throw new Error("GitHub returned an invalid repository file tree.");
    const { candidates, counts } = repositoryCandidates(treeResponse.tree, rules);
    const findings = [];
    const scannedFiles = [];
    const warnings = [
      "Heuristic static analysis only: findings are review leads, not proof of malware; no findings do not prove safety.",
      "Repository files are read directly by your browser from GitHub's public API. No code is executed or sent to this site.",
      "GitHub's unauthenticated API rate limit applies; this scanner never asks for an access token.",
    ];
    if (treeResponse.truncated) warnings.push("GitHub truncated the repository tree; some files may not have been listed.");
    if (counts.ignored_folders) warnings.push("Generated/dependency folders such as node_modules, vendor, build, and dist were excluded.");
    if (counts.scan_limit) warnings.push(`The per-scan cap omitted ${counts.scan_limit} additional supported text files.`);
    if (counts.oversize_files) warnings.push(`Files over ${Math.round(rules.maxFileBytes / 1000)} KB were omitted.`);
    if (counts.unsupported_files) warnings.push(`${counts.unsupported_files} files with unsupported extensions were not inspected as text; binary artifacts are not analyzed.`);
    if (counts.unsafe_paths) warnings.push("Unsafe archive paths were omitted from the file list.");

    updateProgress({ phase: "Inspecting supported text files", current: 0, total: candidates.length, findings: 0 });
    let nextIndex = 0;
    let processed = 0;
    let totalBytes = 0;
    let budgetReached = false;
    let hitRateLimit = false;

    async function worker() {
      while (nextIndex < candidates.length) {
        const index = nextIndex;
        nextIndex += 1;
        const entry = candidates[index];
        if (budgetReached) {
          increment(counts, "byte_budget");
          processed += 1;
          updateProgress({ phase: "Inspecting supported text files", current: processed, total: candidates.length, path: entry.path, findings: findings.length });
          continue;
        }
        try {
          const blob = await githubJson(`/repos/${ownerPath}/${repoPath}/git/blobs/${encodeURIComponent(entry.sha)}`);
          if (!blob || blob.encoding !== "base64" || typeof blob.content !== "string") {
            increment(counts, "unreadable_files");
          } else {
            const decoded = decodeBlob(blob.content);
            if (decoded.error === "binary") {
              increment(counts, "binary_files");
              const nameFinding = suspiciousFilenameFinding(entry.path, rules);
              if (nameFinding) findings.push(nameFinding);
            } else if (decoded.error) {
              increment(counts, "unreadable_files");
            } else if (totalBytes + decoded.byteLength > rules.maxTotalBytes) {
              increment(counts, "byte_budget");
              budgetReached = true;
            } else {
              totalBytes += decoded.byteLength;
              scannedFiles.push(entry.path);
              findings.push(...analyzeText(decoded.text, entry.path, rules));
            }
          }
        } catch (error) {
          increment(counts, "unreadable_files");
          if (error instanceof Error && error.message.toLowerCase().includes("rate limit")) hitRateLimit = true;
        }
        processed += 1;
        updateProgress({ phase: "Inspecting supported text files", current: processed, total: candidates.length, path: entry.path, findings: findings.length });
      }
    }

    const workerCount = Math.min(4, candidates.length);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    if (hitRateLimit) warnings.push("GitHub's API rate limit interrupted part of this scan; results may be incomplete. Wait for the limit to reset.");
    if (counts.unreadable_files && !hitRateLimit) warnings.push("Some files could not be decoded or retrieved; results may be incomplete.");
    if (counts.binary_files) warnings.push(`${counts.binary_files} binary file(s) were skipped. Use a trusted antivirus product for executable/binary analysis.`);
    if (counts.byte_budget) warnings.push(`The ${Math.round(rules.maxTotalBytes / 1_000_000)} MB total text limit was reached; remaining files were omitted.`);
    if (!candidates.length) warnings.push("No supported text files were found in this repository branch.");
    sortFindings(findings);
    const summary = summarize(findings);
    summary.files_scanned = scannedFiles.length;
    summary.files_skipped = Object.values(counts).reduce((sum, value) => sum + value, 0);
    return {
      scan_type: "repository",
      scan_state: "complete",
      repository: {
        full_name: metadata.full_name || `${parsed.owner}/${parsed.repo}`,
        url: metadata.html_url || `https://github.com/${parsed.owner}/${parsed.repo}`,
        branch,
        default_branch: metadata.default_branch,
      },
      summary,
      findings,
      scanned_files: scannedFiles.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())),
      warnings,
      scan_limits: {
        max_files: rules.maxFiles,
        max_file_bytes: rules.maxFileBytes,
        max_total_bytes: rules.maxTotalBytes,
        skip_counts: counts,
      },
    };
  }

  function readFileBuffer(file) {
    if (typeof file.arrayBuffer === "function") return file.arrayBuffer();
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => reader.result instanceof ArrayBuffer ? resolve(reader.result) : reject(new Error("The selected file could not be read."));
      reader.onerror = () => reject(new Error("The selected file could not be read."));
      reader.readAsArrayBuffer(file);
    });
  }

  async function sha256Hex(buffer) {
    if (!globalThis.crypto?.subtle) return null;
    try {
      const digest = await globalThis.crypto.subtle.digest("SHA-256", buffer);
      return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    } catch (_) {
      return null;
    }
  }

  function unsupportedFileReport(fileName, message, rules, fileHash = null) {
    const finding = suspiciousFilenameFinding(fileName, rules);
    const findings = finding ? [finding] : [];
    const summary = summarize(findings);
    summary.risk_label = "Not analyzed";
    summary.files_scanned = 0;
    summary.files_skipped = 1;
    return {
      scan_type: "file",
      scan_state: "unsupported",
      filename: fileName,
      file_sha256: fileHash,
      repository: null,
      summary,
      findings,
      scanned_files: [],
      warnings: [message, "This is a text-signature scanner, not antivirus. No conclusion about binary malware can be made."],
    };
  }

  async function scanUploadedFile(file, rules) {
    updateProgress({ phase: "Reading file locally", current: 0, total: 0 });
    if (!file) throw new Error("Choose a file first.");
    if (file.size > rules.maxFileBytes) {
      return unsupportedFileReport(file.name, `File is ${Math.round(file.size / 1000)} KB; the local text scan limit is ${Math.round(rules.maxFileBytes / 1000)} KB.`, rules);
    }
    const buffer = await readFileBuffer(file);
    const fileHash = await sha256Hex(buffer);
    const bytes = new Uint8Array(buffer);
    if (bytes.includes(0)) return unsupportedFileReport(file.name, "This file contains binary data and was not analyzed.", rules, fileHash);
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch (_) { return unsupportedFileReport(file.name, "This file is not plain UTF-8 text and was not analyzed.", rules, fileHash); }
    if (text.length > rules.maxCodeChars) {
      return unsupportedFileReport(file.name, `Text exceeds the ${Number(rules.maxCodeChars).toLocaleString()}-character local scan limit.`, rules);
    }
    updateProgress({ phase: "Scanning file text locally", current: 1, total: 1 });
    const report = createTextReport("file", file.name, text, rules, "The selected file was read in this browser only; it was not uploaded or stored.");
    report.file_sha256 = fileHash;
    return report;
  }

  async function runScan(request) {
    const rules = await loadRuleSet();
    if (request.mode === "repository") return scanRepository(request, rules);
    if (request.mode === "file") return scanUploadedFile(request.file, rules);
    updateProgress({ phase: "Scanning pasted text locally", current: 0, total: 1 });
    const filename = request.filename || "pasted-snippet.txt";
    const report = createTextReport("snippet", filename, request.code || "", rules, "Pasted text is analyzed in this browser only; it is not uploaded or stored.");
    updateProgress({ phase: "Analysis complete", current: 1, total: 1 });
    return report;
  }

  async function startScan(request) {
    lastRequest = request;
    currentReport = null;
    selectedSeverity = "all";
    searchTerm = "";
    elements.search.value = "";
    showProgress();
    setBusy(true);
    document.getElementById("results-heading").scrollIntoView({ behavior: "smooth", block: "center" });
    try {
      const report = await runScan(request);
      renderReport(report);
    } catch (error) {
      showError(error instanceof Error ? error.message : "The scan could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  elements.repositoryForm.addEventListener("submit", (event) => {
    event.preventDefault();
    startScan({
      mode: "repository",
      repository: elements.repositoryInput.value.trim(),
      branch: elements.branchInput.value.trim(),
    });
  });

  elements.codeForm.addEventListener("submit", (event) => {
    event.preventDefault();
    startScan({
      mode: "code",
      code: elements.codeInput.value,
      filename: elements.filenameInput.value.trim() || "pasted-snippet.txt",
    });
  });

  function selectFile(file) {
    selectedFile = file || null;
    elements.uploadTitle.textContent = selectedFile ? selectedFile.name : "Drop a file here or browse";
    elements.uploadSubtitle.textContent = selectedFile
      ? `${(selectedFile.size / 1024).toFixed(1)} KB · read locally; never uploaded`
      : `Text and source files · max 500 KB · stays on this device`;
    elements.fileButton.disabled = !selectedFile;
  }

  elements.fileInput.addEventListener("change", () => selectFile(elements.fileInput.files?.[0] || null));
  elements.uploadDropzone.addEventListener("dragover", (event) => {
    event.preventDefault();
    elements.uploadDropzone.classList.add("is-dragging");
  });
  elements.uploadDropzone.addEventListener("dragleave", () => elements.uploadDropzone.classList.remove("is-dragging"));
  elements.uploadDropzone.addEventListener("drop", (event) => {
    event.preventDefault();
    elements.uploadDropzone.classList.remove("is-dragging");
    selectFile(event.dataTransfer?.files?.[0] || null);
  });
  elements.fileForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!selectedFile) {
      showError("Choose a file to inspect first.");
      return;
    }
    startScan({ mode: "file", file: selectedFile });
  });

  elements.retry.addEventListener("click", () => {
    if (lastRequest) startScan(lastRequest);
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
    const sourceName = isRepository
      ? (report.repository.full_name || "GitHub repository")
      : (report.filename || report.scanned_files?.[0] || report.findings?.[0]?.path || elements.filenameInput.value.trim() || "Pasted code");
    elements.source.textContent = sourceName;
    elements.branch.textContent = isRepository ? `Branch: ${report.repository.branch || "default"}` : (report.scan_state === "unsupported" ? "Text signatures unavailable" : "Analyzed locally in this browser");
    elements.fileHash.hidden = !report.file_sha256;
    elements.fileHash.textContent = report.file_sha256 ? `SHA-256 ${report.file_sha256}` : "";

    const summary = report.summary || {};
    const score = Math.max(0, Math.min(100, Number(summary.risk_score) || 0));
    const label = report.scan_state === "unsupported" ? "Not analyzed" : (typeof summary.risk_label === "string" ? summary.risk_label : "No indicators");
    elements.riskScore.textContent = String(score);
    elements.riskPill.textContent = label;
    elements.riskPill.className = `risk-pill risk-${label.toLowerCase().replace(/\s+/g, "-")}`;
    setMeter(elements.riskFill, score);
    elements.riskNote.textContent = report.scan_state === "unsupported"
      ? "No text scan was performed. This is not a clean result or a safety verdict."
      : score === 0
        ? "No rule-based indicators matched. This is not proof of safety."
        : "Indicators need human review; a pattern match is not a malware verdict.";
    elements.metricFindings.textContent = String(Number(summary.findings) || 0);
    elements.metricFiles.textContent = String(Number(summary.files_scanned) || 0);
    elements.metricSkipped.textContent = String(Number(summary.files_skipped) || 0);

    const findings = Array.isArray(report.findings) ? report.findings : [];
    renderSeverityFilters(summary.by_severity || {});
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
    detail.append(category);

    if (finding.behavior) {
      const behavior = document.createElement("p");
      const label = document.createElement("strong");
      label.textContent = "Potential behavior if run: ";
      behavior.append(label, document.createTextNode(finding.behavior));
      detail.append(behavior);
    }
    if (finding.install_effect) {
      const installEffect = document.createElement("p");
      const label = document.createElement("strong");
      label.textContent = "Install-time caveat: ";
      installEffect.append(label, document.createTextNode(finding.install_effect));
      detail.append(installEffect);
    }
    const recommendation = document.createElement("p");
    const recommendationLabel = document.createElement("strong");
    recommendationLabel.textContent = "Suggested review: ";
    recommendation.append(recommendationLabel, document.createTextNode(finding.recommendation || "Do not run untrusted code; verify its source and behavior."));
    detail.append(recommendation);
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
      const haystack = [finding.title, finding.category, finding.path, finding.summary, finding.behavior, finding.install_effect, finding.evidence]
        .filter(Boolean).join(" ").toLowerCase();
      return haystack.includes(searchTerm);
    });
    elements.findingsList.replaceChildren(...filtered.map(createFindingCard));
    elements.findingsEmpty.hidden = filtered.length !== 0;
    elements.findingsList.hidden = filtered.length === 0;
    elements.findingsEmpty.textContent = currentReport?.scan_state === "unsupported" && filtered.length === 0
      ? "This file could not be checked by text-based rules. See the note below."
      : "No indicators match this filter.";
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
    const base = (currentReport.repository?.full_name || currentReport.filename || "scan-report").replace(/[^A-Za-z0-9._-]+/g, "-");
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

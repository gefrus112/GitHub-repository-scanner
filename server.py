#!/usr/bin/env python3
"""Defensive, static-only GitHub repository scanner (Python standard library only)."""

from __future__ import annotations

import io
import json
import os
import re
import threading
import time
import zipfile
from collections import Counter, defaultdict, deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
MAX_BODY_BYTES = 1_500_000
MAX_SNIPPET_CHARS = 240
MAX_CODE_CHARS = 250_000
MAX_FILES_PER_REPO_SCAN = 50
MAX_BLOB_BYTES = 500_000
MAX_TOTAL_BYTES = 8_000_000
MAX_ARCHIVE_BYTES = 24_000_000
MAX_GITHUB_RESPONSE_BYTES = 2_000_000
GITHUB_API = "https://api.github.com"
SUSPICIOUS_FILENAME = re.compile(
    r"(?:^|[-_.\s])(?:stealer|keylogger|keylog|cryptominer|miner|trojan|rat|webshell|crypter|injector|dropper|payload|redline)(?:[-_.\s]|$)",
    re.IGNORECASE,
)

# These are intentionally explainable heuristics, not a malware verdict or AV engine.
RULES: list[dict[str, Any]] = [
    {
        "id": "discord-webhook",
        "title": "Discord webhook endpoint",
        "severity": "high",
        "category": "Webhook / data transfer",
        "pattern": re.compile(
            r"https?://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/webhooks/\d{6,}/[A-Za-z0-9._-]{12,}",
            re.IGNORECASE,
        ),
        "summary": "A hard-coded Discord webhook can be used to send collected data out of the repository.",
        "recommendation": "Check who owns the webhook, what data reaches it, and whether the endpoint is expected. Revoke any exposed webhook token.",
    },
    {
        "id": "telegram-bot-exfiltration",
        "title": "Telegram bot API endpoint",
        "severity": "high",
        "category": "Webhook / data transfer",
        "pattern": re.compile(
            r"https?://api\.telegram\.org/bot[^/\s\"'`]+/(?:sendMessage|sendDocument|sendPhoto|sendAudio|sendVideo)",
            re.IGNORECASE,
        ),
        "summary": "A Telegram bot endpoint can be used as a covert channel for sending data or files.",
        "recommendation": "Trace the data passed to this request and verify that the bot and recipient are authorized.",
    },
    {
        "id": "crypto-miner",
        "title": "Cryptomining indicator",
        "severity": "high",
        "category": "Cryptomining",
        "pattern": re.compile(
            r"(?:stratum\+(?:tcp|ssl)://|\bxmrig\b|\bcoinhive\b|\bcryptonight\b|\brandomx\b)",
            re.IGNORECASE,
        ),
        "summary": "A mining protocol, miner name, or mining algorithm is referenced.",
        "recommendation": "Inspect the surrounding code for unauthorized mining, pool connections, and resource use.",
    },
    {
        "id": "encoded-powershell",
        "title": "Encoded PowerShell command",
        "severity": "high",
        "category": "Obfuscation / execution",
        "pattern": re.compile(
            r"\bpowershell(?:\.exe)?\b[^\r\n]{0,140}-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
            re.IGNORECASE,
        ),
        "summary": "PowerShell is launched with a long encoded command, a technique that can conceal behavior.",
        "recommendation": "Do not execute it. Decode and review the command in an isolated, offline analysis environment.",
    },
    {
        "id": "download-and-execute",
        "title": "Download followed by execution",
        "severity": "high",
        "category": "Downloader / execution",
        "pattern": re.compile(
            r"(?:(?:invoke-webrequest|\biwr\b|downloadstring|start-bitstransfer|\bcurl\b|\bwget\b)[^\r\n]{0,180}(?:\biex\b|invoke-expression|\|\s*(?:sh|bash|pwsh|powershell)))",
            re.IGNORECASE,
        ),
        "summary": "A network download appears connected to a command interpreter or dynamic execution.",
        "recommendation": "Follow the downloaded content and verify its source and integrity before allowing any execution.",
    },
    {
        "id": "dynamic-base64-execution",
        "title": "Obfuscated content passed to an execution function",
        "severity": "high",
        "category": "Obfuscation / execution",
        "pattern": re.compile(
            r"(?:(?:\beval\b|\bexec\b|invoke-expression|\biex\b)[^\r\n]{0,120}(?:atob|b64decode|frombase64string)|(?:atob|b64decode|frombase64string)\s*\([^\r\n]{0,120}(?:\beval\b|\bexec\b|\biex\b))",
            re.IGNORECASE,
        ),
        "summary": "Base64-decoded or browser-decoded text is near a dynamic execution call.",
        "recommendation": "Treat the decoded content as untrusted and inspect it without running it.",
    },
    {
        "id": "php-webshell",
        "title": "PHP web-shell pattern",
        "severity": "critical",
        "category": "Remote command execution",
        "pattern": re.compile(
            r"(?:eval\s*\(\s*base64_decode\s*\(|assert\s*\(\s*\$_(?:GET|POST|REQUEST)|(?:passthru|shell_exec|system)\s*\(\s*\$_(?:GET|POST|REQUEST))",
            re.IGNORECASE,
        ),
        "summary": "Request-controlled input appears to reach a PHP execution primitive or encoded payload.",
        "recommendation": "Do not expose this file to a web server. Review the full request-to-execution path and remove unauthorized access.",
    },
    {
        "id": "process-injection",
        "title": "Process injection API",
        "severity": "critical",
        "category": "Process injection",
        "pattern": re.compile(
            r"\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx)\b",
            re.IGNORECASE,
        ),
        "summary": "A Windows API commonly associated with writing into or starting code inside another process is present.",
        "recommendation": "Confirm this is required, authorized software behavior; inspect surrounding code and its origin carefully.",
    },
    {
        "id": "keylogger-hook",
        "title": "Keyboard capture hook",
        "severity": "high",
        "category": "Credential / input capture",
        "pattern": re.compile(
            r"\b(?:SetWindowsHookEx(?:A|W)?|GetAsyncKeyState|keylogger)\b|pynput\.keyboard|keyboard\.Listener",
            re.IGNORECASE,
        ),
        "summary": "A keyboard capture API or keylogger marker is present.",
        "recommendation": "Verify that keystrokes are not recorded or transmitted without the user's informed consent.",
    },
    {
        "id": "browser-credential-store",
        "title": "Browser credential-store access",
        "severity": "high",
        "category": "Credential theft",
        "pattern": re.compile(
            r"(?:[\\/]+Google[\\/]+Chrome[\\/]+User Data[\\/]+(?:Default[\\/]+)?(?:Login Data|Local State)|[\\/]+Mozilla[\\/]+Firefox[\\/]+Profiles[\\/]+[^\s\"']+[\\/]+(?:key4\.db|logins\.json)|\b(?:Login Data|key4\.db|logins\.json)\b)",
            re.IGNORECASE,
        ),
        "summary": "A browser password or cookie database path is referenced.",
        "recommendation": "Check whether the file is being accessed for a legitimate migration or backup, and whether its contents leave the machine.",
    },
    {
        "id": "discord-token-storage",
        "title": "Discord local-token storage reference",
        "severity": "high",
        "category": "Credential theft",
        "pattern": re.compile(
            r"(?:discord[^\r\n]{0,100}(?:leveldb|local storage)|(?:leveldb|local storage)[^\r\n]{0,100}discord)",
            re.IGNORECASE,
        ),
        "summary": "Discord client token-storage locations are referenced.",
        "recommendation": "Inspect for token harvesting and outbound transfer; rotate credentials if a token may have been exposed.",
    },
    {
        "id": "wallet-secret-theft",
        "title": "Wallet recovery-secret handling",
        "severity": "high",
        "category": "Crypto wallet theft",
        "pattern": re.compile(
            r"(?:(?:seed phrase|recovery phrase|mnemonic|private key)[^\r\n]{0,100}(?:wallet|webhook|discord|send|steal|upload|post)|(?:wallet|crypto)[^\r\n]{0,100}(?:seed phrase|recovery phrase|mnemonic|private key))",
            re.IGNORECASE,
        ),
        "summary": "Wallet recovery phrases or private keys appear near transfer or collection logic.",
        "recommendation": "Never enter a real recovery phrase. Verify the code's purpose and assume any exposed secret is compromised.",
    },
    {
        "id": "reverse-shell",
        "title": "Reverse-shell command pattern",
        "severity": "critical",
        "category": "Remote command execution",
        "pattern": re.compile(
            r"(?:bash\s+-i\s+>&\s*/dev/tcp/|\bnc(?:at)?\s+-e\s+/bin/(?:ba)?sh|\bsocket\.socket\s*\([^\r\n]{0,100}\)\s*\.\s*connect\s*\()",
            re.IGNORECASE,
        ),
        "summary": "A shell or socket appears configured to call back to a remote host.",
        "recommendation": "Do not run the file. Confirm whether remote command access is intentional and restrict network exposure.",
    },
    {
        "id": "windows-persistence",
        "title": "Windows autorun or scheduled-task persistence",
        "severity": "medium",
        "category": "Persistence",
        "pattern": re.compile(
            r"(?:HKEY_CURRENT_USER[\\/]+Software[\\/]+Microsoft[\\/]+Windows[\\/]+CurrentVersion[\\/]+Run|HKCU[\\/]+Software[\\/]+Microsoft[\\/]+Windows[\\/]+CurrentVersion[\\/]+Run|schtasks(?:\.exe)?\s+/create|[\\/]+Startup[\\/]+)",
            re.IGNORECASE,
        ),
        "summary": "A registry autorun location, Startup folder, or scheduled-task creation command is referenced.",
        "recommendation": "Check what is being made persistent, whether the user is informed, and how it can be removed.",
    },
    {
        "id": "hidden-powershell",
        "title": "Hidden PowerShell window",
        "severity": "medium",
        "category": "Stealth / execution",
        "pattern": re.compile(
            r"\bpowershell(?:\.exe)?\b[^\r\n]{0,100}(?:-windowstyle\s+hidden|-w\s+hidden)",
            re.IGNORECASE,
        ),
        "summary": "PowerShell is started with its window hidden, which can conceal activity from the user.",
        "recommendation": "Inspect the command and its parent process; legitimate administration tools should document this behavior.",
    },
    {
        "id": "ransomware-or-wipe-command",
        "title": "Destructive or shadow-copy deletion command",
        "severity": "high",
        "category": "Destructive behavior",
        "pattern": re.compile(
            r"(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|cipher(?:\.exe)?\s+/w:|format\s+[a-z]:\s|remove-item[^\r\n]{0,100}-recurse[^\r\n]{0,100}-force)",
            re.IGNORECASE,
        ),
        "summary": "A command can remove recovery data or recursively delete files.",
        "recommendation": "Confirm this destructive operation is explicitly intended and protected by backups and authorization.",
    },
    {
        "id": "package-install-hook",
        "title": "Package install lifecycle hook",
        "severity": "low",
        "category": "Install-time behavior",
        "pattern": re.compile(r"[\"'](?:preinstall|install|postinstall)[\"']\s*:", re.IGNORECASE),
        "summary": "A package lifecycle script runs automatically during installation; this is common but deserves review.",
        "recommendation": "Inspect the exact command and any files or network locations it invokes before installing the package.",
    },
]

SCANNABLE_SUFFIXES = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".php", ".phtml", ".rb", ".go", ".rs", ".java", ".kt", ".kts", ".scala", ".groovy",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".fs", ".vb", ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".vbs", ".vbe", ".hta", ".sh", ".bash", ".zsh", ".fish", ".pl", ".pm",
    ".lua", ".r", ".sql", ".html", ".htm", ".xml", ".xsl", ".svg", ".json", ".jsonc", ".ipynb",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".txt", ".md",
    ".rst", ".lock", ".make", ".gradle", ".tf", ".hcl", ".dockerignore", ".gitignore",
    ".swift", ".m", ".mm", ".dart", ".ex", ".exs", ".erl", ".hrl", ".clj", ".cljs", ".cljc",
    ".hs", ".lhs", ".ml", ".mli", ".f", ".f90", ".pas", ".pp", ".asm", ".sv", ".scss",
    ".css", ".less", ".map", ".resx", ".csproj", ".sln", ".service", ".desktop", ".plist",
    ".reg", ".wsf", ".wsh", ".inf", ".manifest", ".config", ".list", ".aspx", ".jsp", ".jspx",
    ".ejs", ".pug", ".hbs", ".liquid",
}
SCANNABLE_BASENAMES = {
    "dockerfile", "makefile", "gemfile", "rakefile", "procfile", "justfile", "cmakelists.txt",
    "readme", "license", "licence", "notice", "contributing", "changelog", "changes", "authors",
    "copying", "todo", "version", "entrypoint", "install", "setup", "start", "run", "update",
    ".env", ".env.example", ".env.sample", ".npmrc", ".pypirc", ".dockerignore", ".editorconfig",
    ".gitattributes", ".gitmodules", "requirements.txt", "pyproject.toml", "package.json",
    "composer.json", "go.mod", "cargo.toml",
}
IGNORED_DIRECTORY_NAMES = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "coverage", ".next",
    ".nuxt", ".venv", "venv", "__pycache__", "site-packages",
}
SCRIPT_SUFFIXES = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".ps1", ".psm1",
    ".bat", ".cmd", ".vbs", ".vbe", ".hta", ".sh", ".bash", ".zsh", ".rb", ".pl",
}
SEVERITY_WEIGHT = {"critical": 45, "high": 30, "medium": 15, "low": 5}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ScanError(Exception):
    """An expected input, GitHub API, or scan limitation error."""


def _redact_evidence(text: str) -> str:
    """Mask common credentials before an evidence line is shown in the browser."""
    redactions = [
        (r"(?i)(https?://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/webhooks/)[^\s\"'<>]+", r"\1[REDACTED]"),
        (r"(?i)(https?://api\.telegram\.org/bot)[^/\s\"'<>]+", r"\1[REDACTED]"),
        (r"\bgh[pousr]_[A-Za-z0-9_]{10,}\b", "[REDACTED_TOKEN]"),
        (r"(?i)(\b(?:bearer|authorization)\s*[:= ]\s*)[A-Za-z0-9._~+/-]{12,}=*", r"\1[REDACTED]"),
        (r"(?i)(\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|webhook[_-]?token|github[_-]?token|token|secret|password|private[_-]?key)\b\s*[:=]\s*[\"']?)[^\s\"'`,;]{8,}", r"\1[REDACTED]"),
    ]
    for pattern, replacement in redactions:
        text = re.sub(pattern, replacement, text)
    text = text.strip()
    if len(text) > MAX_SNIPPET_CHARS:
        text = text[: MAX_SNIPPET_CHARS - 1] + "…"
    return text


def suspicious_filename_finding(path: str) -> dict[str, Any] | None:
    filename = path.replace("\\", "/").rsplit("/", 1)[-1]
    if not SUSPICIOUS_FILENAME.search(filename):
        return None
    return {
        "id": "suspicious-filename",
        "title": "Suspicious filename keyword",
        "severity": "low",
        "category": "File metadata",
        "path": path,
        "line": 1,
        "evidence": _redact_evidence(f"Filename: {filename}"),
        "summary": "The filename contains a term often associated with malware. A name alone is a weak signal, not proof of malicious behavior.",
        "recommendation": "Review the file contents and provenance; do not judge safety by filename alone.",
    }


def analyze_text(text: str, path: str = "pasted-snippet.txt") -> list[dict[str, Any]]:
    """Return heuristic findings for UTF-8 text. Does not execute or persist input."""
    text = text[:MAX_CODE_CHARS]
    found: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                found.append(
                    {
                        "id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "path": path,
                        "line": line_number,
                        "evidence": _redact_evidence(line),
                        "summary": rule["summary"],
                        "recommendation": rule["recommendation"],
                    }
                )
                if len(found) >= 250:
                    return found
    filename_finding = suspicious_filename_finding(path)
    if filename_finding:
        found.append(filename_finding)
    return found


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = Counter(item["severity"] for item in findings)
    # Count each distinct detector only once so repeated copies of a line do not inflate the score.
    unique_rules = {item["id"]: item["severity"] for item in findings}
    score = min(100, sum(SEVERITY_WEIGHT[severity] for severity in unique_rules.values()))
    if score >= 70:
        label = "Critical"
    elif score >= 45:
        label = "High"
    elif score >= 20:
        label = "Elevated"
    elif score > 0:
        label = "Guarded"
    else:
        label = "No indicators"
    return {
        "risk_score": score,
        "risk_label": label,
        "findings": len(findings),
        "by_severity": {
            severity: severity_counts.get(severity, 0)
            for severity in ("critical", "high", "medium", "low")
        },
    }


def scan_code(code: str, filename: str = "pasted-snippet.txt") -> dict[str, Any]:
    if not isinstance(code, str) or not code.strip():
        raise ScanError("Paste some text or source code to scan.")
    if len(code) > MAX_CODE_CHARS:
        raise ScanError(f"Pasted text exceeds the {MAX_CODE_CHARS:,}-character limit.")
    safe_filename = filename.strip().replace("\\", "/").split("/")[-1][:120] or "pasted-snippet.txt"
    findings = analyze_text(code, safe_filename)
    summary = summarize(findings)
    return {
        "scan_type": "snippet",
        "repository": None,
        "summary": {**summary, "files_scanned": 1, "files_skipped": 0},
        "findings": findings,
        "scanned_files": [safe_filename],
        "warnings": [
            "This is a heuristic static scan, not a malware verdict. A clean result does not prove the code is safe.",
            "Pasted content is analyzed in memory only; it is not saved by this service.",
        ],
    }


def parse_github_repository(raw: str, branch_override: str = "") -> tuple[str, str, str | None]:
    """Accept only canonical public GitHub repository links or owner/repo shorthand."""
    value = raw.strip()
    if not value:
        raise ScanError("Enter a GitHub repository URL or owner/repository.")
    if len(value) > 2048:
        raise ScanError("Repository URL is too long.")

    if "://" not in value and value.lower().startswith("github.com/"):
        value = "https://" + value

    parsed_branch: str | None = None
    if "://" in value:
        parsed = urlparse(value)
        try:
            hostname = parsed.hostname or ""
            port = parsed.port
        except ValueError as exc:
            raise ScanError("That GitHub URL has an invalid port.") from exc
        if parsed.scheme.lower() != "https" or hostname.lower() not in {"github.com", "www.github.com"}:
            raise ScanError("For safety, enter a public repository link from https://github.com only.")
        if parsed.username or parsed.password or port not in (None, 443):
            raise ScanError("That GitHub URL contains an unsupported host or credentials.")
        segments = [unquote(part) for part in parsed.path.split("/") if part]
    else:
        segments = [unquote(part) for part in value.split("/") if part]

    if len(segments) < 2:
        raise ScanError("Use a repository link like https://github.com/owner/repository.")
    owner, repo = segments[0], segments[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or owner in {".", ".."}:
        raise ScanError("The repository owner contains unsupported characters.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo) or repo in {".", ".."}:
        raise ScanError("The repository name contains unsupported characters.")

    # Repository root and tree/blob links are accepted. For branch names containing '/', use the branch box.
    if len(segments) > 2:
        if len(segments) >= 4 and segments[2] in {"tree", "blob"}:
            parsed_branch = segments[3]
        else:
            raise ScanError("Paste a repository root link, or a /tree/branch or /blob/branch link.")

    branch = branch_override.strip() or parsed_branch
    if branch:
        if len(branch) > 200 or any(char in branch for char in ("\x00", "\r", "\n")):
            raise ScanError("Branch name is invalid or too long.")
        if branch.startswith("-"):
            raise ScanError("Branch names beginning with a dash are not supported.")
        if any(part in {"", ".", ".."} for part in branch.split("/")):
            raise ScanError("Branch name contains an unsupported path segment.")
    return owner, repo, branch


def _github_json(path: str) -> Any:
    if not path.startswith("/") or path.startswith("//"):
        raise ScanError("Invalid GitHub API path.")
    request = Request(
        GITHUB_API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Repo-Safety-Scanner/1.0",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=18) as response:
            raw = response.read(MAX_GITHUB_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 403:
            raise ScanError("GitHub's unauthenticated API limit was reached. Wait a while, then try again.") from exc
        if exc.code == 404:
            raise ScanError("Repository or branch not found. Private repositories are not supported.") from exc
        if exc.code == 451:
            raise ScanError("GitHub cannot provide this repository from the current location.") from exc
        raise ScanError(f"GitHub API returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ScanError("Could not connect to GitHub's API. Check your connection and retry.") from exc

    if len(raw) > MAX_GITHUB_RESPONSE_BYTES:
        raise ScanError("GitHub returned a response that is too large for this scanner.")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanError("GitHub returned an unreadable API response.") from exc


def _download_archive(owner: str, repo: str, branch: str) -> bytes:
    """Fetch one bounded public-source archive instead of consuming an API call per file."""
    url = (
        f"https://codeload.github.com/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/zip/refs/heads/{quote(branch, safe='/')}"
    )
    request = Request(
        url,
        headers={"Accept": "application/zip", "User-Agent": "Repo-Safety-Scanner/1.0"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=35) as response:
            raw = response.read(MAX_ARCHIVE_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise ScanError("Repository branch archive not found. Private repositories are not supported.") from exc
        if exc.code == 403:
            raise ScanError("GitHub declined the archive request. Try again later or scan a smaller public repository.") from exc
        raise ScanError(f"GitHub archive service returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ScanError("Could not download the public GitHub archive. Check your connection and retry.") from exc
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ScanError("This repository archive exceeds the scanner's 24 MB download limit.")
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        raise ScanError("GitHub returned an invalid repository archive.")
    return raw


def _file_priority(entry: dict[str, Any]) -> tuple[int, int, str]:
    path = entry.get("path", "")
    name = path.rsplit("/", 1)[-1]
    suffix = Path(name).suffix.lower()
    lowered = path.lower()
    priority = 1 if suffix in SCRIPT_SUFFIXES or name.lower() in {"dockerfile", "makefile", ".env"} else 2
    if any(word in lowered for word in ("stealer", "keylog", "miner", "webhook", "loader", "inject", "trojan", "payload")):
        priority = 0
    if name.lower().endswith(".min.js") or name.lower() in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "cargo.lock"}:
        priority += 3
    return priority, len(path), path.lower()


def _eligible_tree_entries(tree: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    counts = Counter()
    candidates: list[dict[str, Any]] = []
    for entry in tree:
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if not isinstance(path, str):
            continue
        components = path.split("/")
        if any(part.lower() in IGNORED_DIRECTORY_NAMES for part in components[:-1]):
            counts["ignored_folders"] += 1
            continue
        name = components[-1]
        suffix = Path(name).suffix.lower()
        suspicious_name = SUSPICIOUS_FILENAME.search(name) is not None
        if suffix not in SCANNABLE_SUFFIXES and name.lower() not in SCANNABLE_BASENAMES and not suspicious_name:
            counts["unsupported_files"] += 1
            continue
        if name.lower().endswith(".min.js") or name.lower() in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "cargo.lock"}:
            counts["generated_or_lockfiles"] += 1
            continue
        size = entry.get("size", 0)
        if not isinstance(size, int) or size < 0 or size > MAX_BLOB_BYTES:
            counts["oversize_files"] += 1
            continue
        candidates.append(entry)
    candidates.sort(key=_file_priority)
    if len(candidates) > MAX_FILES_PER_REPO_SCAN:
        counts["scan_limit"] = len(candidates) - MAX_FILES_PER_REPO_SCAN
        candidates = candidates[:MAX_FILES_PER_REPO_SCAN]
    return candidates, dict(counts)


def scan_github_repository(
    repository_input: str,
    branch_override: str = "",
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    emit = progress or (lambda _event: None)
    owner, repo, requested_branch = parse_github_repository(repository_input, branch_override)
    emit({"phase": "Loading repository details", "current": 0, "total": 0})

    metadata = _github_json(f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}")
    if not isinstance(metadata, dict) or not metadata.get("default_branch"):
        raise ScanError("GitHub did not return repository metadata.")
    branch = requested_branch or metadata["default_branch"]
    emit({"phase": f"Downloading the {branch} branch archive", "current": 0, "total": 0})
    archive_bytes = _download_archive(owner, repo, branch)

    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ScanError("GitHub returned an invalid repository archive.") from exc

    # GitHub archives have one top-level directory. Strip it, reject unsafe path segments,
    # and never extract archive entries onto disk.
    archive_entries: list[dict[str, Any]] = []
    archive_files: dict[str, zipfile.ZipInfo] = {}
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            archive_path = info.filename.replace("\\", "/")
            parts = archive_path.split("/")
            if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts):
                continue
            relative_path = "/".join(parts[1:])
            archive_files[relative_path] = info
            archive_entries.append({
                "type": "blob",
                "path": relative_path,
                "size": info.file_size,
            })
        candidates, skip_counts = _eligible_tree_entries(archive_entries)
        warnings: list[str] = [
            "Heuristic static analysis only: findings are indicators to review, not proof of malware; no findings do not prove safety.",
            "No repository code is executed. Binary files are not analyzed. Private repositories are not supported.",
        ]
        if skip_counts.get("ignored_folders"):
            warnings.append("Generated and dependency folders (such as node_modules, vendor, build, and dist) were excluded.")
        if skip_counts.get("scan_limit"):
            warnings.append(f"The per-scan cap omitted {skip_counts['scan_limit']} additional supported text files.")
        if skip_counts.get("oversize_files"):
            warnings.append("One or more files exceeded the scanner's 500 KB per-file text limit.")

        emit({"phase": "Inspecting supported text files", "current": 0, "total": len(candidates)})
        findings: list[dict[str, Any]] = []
        scanned_files: list[str] = []
        scanned = 0
        total_bytes = 0
        processed = 0
        for index, entry in enumerate(candidates):
            path = entry["path"]
            info = archive_files[path]
            processed = index + 1
            if total_bytes >= MAX_TOTAL_BYTES:
                skip_counts["byte_budget"] = skip_counts.get("byte_budget", 0) + len(candidates) - index
                emit({
                    "phase": "Inspecting supported text files",
                    "current": len(candidates),
                    "total": len(candidates),
                    "path": path,
                })
                break
            try:
                with archive.open(info) as source:
                    raw = source.read(MAX_BLOB_BYTES + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile, EOFError):
                skip_counts["unreadable_files"] = skip_counts.get("unreadable_files", 0) + 1
                emit({"phase": "Inspecting supported text files", "current": processed, "total": len(candidates), "path": path})
                continue
            if len(raw) > MAX_BLOB_BYTES:
                skip_counts["oversize_files"] = skip_counts.get("oversize_files", 0) + 1
            elif b"\x00" in raw:
                skip_counts["binary_files"] = skip_counts.get("binary_files", 0) + 1
                filename_finding = suspicious_filename_finding(path)
                if filename_finding:
                    findings.append(filename_finding)
            elif total_bytes + len(raw) > MAX_TOTAL_BYTES:
                skip_counts["byte_budget"] = skip_counts.get("byte_budget", 0) + len(candidates) - index
                emit({
                    "phase": "Inspecting supported text files",
                    "current": len(candidates),
                    "total": len(candidates),
                    "path": path,
                })
                break
            else:
                content = raw.decode("utf-8", errors="replace")
                total_bytes += len(raw)
                scanned += 1
                scanned_files.append(path)
                findings.extend(analyze_text(content, path))
            emit({"phase": "Inspecting supported text files", "current": processed, "total": len(candidates), "path": path})
            if len(findings) >= 250:
                findings = findings[:250]
                unprocessed = len(candidates) - processed
                if unprocessed:
                    skip_counts["finding_limit"] = unprocessed
                warnings.append("Finding output was capped at 250 indicators; remaining candidate files were not inspected.")
                break

        if skip_counts.get("byte_budget"):
            warnings.append("The 8 MB total text budget was reached; remaining files were omitted.")
        if skip_counts.get("binary_files"):
            warnings.append("One or more binary artifacts were omitted; executable contents are not analyzed by this scanner.")
        if not candidates:
            warnings.append("No supported text files were found in this repository branch.")

    # Stable, scannable ordering: more severe indicators first, then file and line.
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["path"].lower(), item["line"], item["id"]))
    summary = summarize(findings)
    omitted = sum(skip_counts.values())
    summary.update({"files_scanned": scanned, "files_skipped": omitted})
    return {
        "scan_type": "repository",
        "repository": {
            "full_name": metadata.get("full_name", f"{owner}/{repo}"),
            "url": metadata.get("html_url", f"https://github.com/{owner}/{repo}"),
            "branch": branch,
            "default_branch": metadata["default_branch"],
        },
        "summary": summary,
        "findings": findings,
        "scanned_files": scanned_files,
        "warnings": warnings,
        "scan_limits": {
            "max_archive_bytes": MAX_ARCHIVE_BYTES,
            "max_files": MAX_FILES_PER_REPO_SCAN,
            "max_file_bytes": MAX_BLOB_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
            "skip_counts": skip_counts,
        },
    }


class ScannerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    _rate_lock = threading.Lock()
    _recent_requests: dict[str, deque[float]] = defaultdict(deque)
    _scan_slots = threading.BoundedSemaphore(3)

    def allow_scan(self, address: str) -> bool:
        now = time.monotonic()
        with self._rate_lock:
            recent = self._recent_requests[address]
            while recent and now - recent[0] > 60:
                recent.popleft()
            if len(recent) >= 20:
                return False
            recent.append(now)
            return True

    def acquire_scan(self) -> bool:
        return self._scan_slots.acquire(blocking=False)

    def release_scan(self) -> None:
        self._scan_slots.release()


class RequestHandler(SimpleHTTPRequestHandler):
    server_version = "RepoSafetyScanner/1.0"
    sys_version = ""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        super().end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep logs concise; avoid reflecting request payloads or source code.
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")

    def _json_response(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/api/health":
            self._json_response(200, {
                "status": "ok",
                "scanner": "static-only",
                "github_public_repositories": True,
                "vm_sandbox": {"connected": False, "execution_enabled": False},
            })
            return
        if self.path.startswith("/api/"):
            self._json_response(404, {"error": "API endpoint not found."})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path not in {"/api/scan/repository", "/api/scan/code"}:
            self._json_response(404, {"error": "API endpoint not found."})
            return
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except ValueError:
            self._json_response(411, {"error": "A valid Content-Length header is required."})
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._json_response(413, {"error": f"Request body exceeds the {MAX_BODY_BYTES:,}-byte limit."})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json_response(400, {"error": "Request body must be valid JSON."})
            return
        if not isinstance(payload, dict):
            self._json_response(400, {"error": "Request JSON must be an object."})
            return
        address = self.client_address[0]
        if not self.server.allow_scan(address):
            self._json_response(429, {"error": "Scan limit reached for this address. Please wait a minute and retry."})
            return
        if not self.server.acquire_scan():
            self._json_response(503, {"error": "The scanner is busy. Wait for an active scan to finish, then retry."})
            return

        # The stream is closed at the end of the response; no arbitrary remote URL or code execution is allowed.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def send_event(event_name: str, data: dict[str, Any]) -> None:
            packet = f"event: {event_name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8")
            self.wfile.write(packet)
            self.wfile.flush()

        try:
            if self.path == "/api/scan/repository":
                repository = payload.get("repository", "")
                branch = payload.get("branch", "")
                if not isinstance(repository, str) or not isinstance(branch, str):
                    raise ScanError("Repository and branch must be text values.")
                result = scan_github_repository(repository, branch, send_event)
            else:
                code = payload.get("code", "")
                filename = payload.get("filename", "pasted-snippet.txt")
                if not isinstance(code, str) or not isinstance(filename, str):
                    raise ScanError("Code and filename must be text values.")
                send_event("progress", {"phase": "Checking pasted text", "current": 0, "total": 1})
                result = scan_code(code, filename)
                send_event("progress", {"phase": "Analysis complete", "current": 1, "total": 1})
            send_event("result", result)
        except ScanError as exc:
            try:
                send_event("error", {"message": str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # Keep internal details out of the client response.
            print(f"Scan error: {type(exc).__name__}")
            try:
                send_event("error", {"message": "The scan could not be completed. Check the server log and try again."})
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            self.server.release_scan()


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    server = ScannerHTTPServer((host, port), RequestHandler)
    print(f"Repository Safety Scanner listening on http://{host}:{port}")
    print("Static analysis only. No submitted or downloaded code is executed.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down scanner server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

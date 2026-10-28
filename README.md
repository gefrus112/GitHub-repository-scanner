# Repository Safety Scanner

A browser-first static scanner for public GitHub repositories, pasted source, and local text files. Explainable rules flag suspicious indicators including Discord/Telegram endpoints, cryptomining strings, encoded or downloaded execution, persistence hooks, credential-store references, reverse shells, process-injection APIs, and suspicious filenames. Each finding includes a cautious behavior explanation and a review recommendation.

> **Not antivirus.** Rules are heuristics, not a malware verdict. A match needs human review, and a clean result does not prove safety. Binary executables are not analyzed or run.

## GitHub Pages

The workflow in `.github/workflows/pages.yml` publishes the `web/` application on pushes to `main` and on manual dispatch. It publishes the scanner app rather than the repository README. A root `index.html` also redirects older branch-based Pages builds to `web/`, so the README is no longer the site landing page. For an Actions-only deployment, set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**; the redirect also covers existing branch-based configurations. The project site is `https://gefrus112.github.io/GitHub-repository-scanner/`.

The Pages app runs scans in the browser. For a repository scan it reads public repository metadata, the file tree, and selected text blobs directly from `api.github.com`; pasted code and selected files stay in the browser. GitHub's unauthenticated API rate limit applies. The app asks for no GitHub token and has no database or analytics code.

## Local use

Requires Python 3.10+ with no third-party dependencies:

```bash
python3 server.py
```

Open <http://localhost:8000>. The web interface works locally and also has a small Python API for local integrations. Configure a different port with `PORT=8080 python3 server.py`; the default bind is `0.0.0.0` for the Arena preview.

Available same-origin endpoints:

- `GET /api/health` — reports static scanner and VM-host status.
- `POST /api/scan/repository` — streams a static GitHub repository scan as Server-Sent Events. JSON body: `{"repository":"https://github.com/owner/repo","branch":"optional-branch"}`.
- `POST /api/scan/code` — scans pasted UTF-8 text in memory. JSON body: `{"filename":"sample.ps1","code":"..."}`.

Repository scans are capped at 50 candidate files, 500 KB per file, and 8 MB total decoded text; generated/dependency folders are excluded. The browser scanner uses GitHub's unauthenticated API, so repeated scans can reach its rate limit. Text file uploads are read locally (500 KB maximum). Binary formats are reported as unsupported rather than being treated as clean.

## Safe-use and data notes

- The browser UI does not upload pasted text or selected files, save reports, or execute code. Public repository requests go directly from the browser to GitHub, which may log normal request metadata.
- The Python API does not write submitted text or downloaded repository content to disk. Keep the API on a trusted network unless placed behind authentication and access controls.
- No VM host or other Arena agent is connected. The Windows section is guidance only; there is no automated VM launch or dynamic malware execution. For deeper review, use a disposable, patched Windows VM you control: note the sample source and SHA-256, take a clean snapshot, disable networking and host-sharing features, transfer samples only through controlled read-only media, use no real credentials, then revert or destroy the guest.
- Never expose RDP, VNC, or VM-control ports through a public link or tunnel. If network behavior must be studied, use a private isolated lab with simulated services and experienced supervision; virtualization is not a guarantee against escape.
- Behavior notes are conditional explanations of what a matched pattern *could* do if reached. They cannot establish whether a file is malicious or what a complete installer will do.

## Tests

```bash
python3 -m unittest discover -s tests -v
node --check web/app.js
```

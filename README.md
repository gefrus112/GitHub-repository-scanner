# Repository Safety Scanner

A small, defensive scanner for suspicious files in **public GitHub repositories** and pasted source. It uses transparent static rules to flag indicators such as suspicious filenames, Discord/Telegram webhook endpoints, cryptomining strings, encoded or downloaded command execution, persistence hooks, credential-store references, reverse shells, and process-injection APIs.

> **Static analysis only.** This application never executes, builds, or launches code from a repository. It is not antivirus software; a finding is a lead for human review, and a clean scan does not prove that code is safe. Binary files are not analyzed.

## Run locally

Requires Python 3.10+ and has no third-party dependencies.

```bash
python3 server.py
```

Open <http://localhost:8000>. To choose another port, set `PORT`; to change the bind address, set `HOST` (default `0.0.0.0` for the Arena preview).

```bash
PORT=8080 python3 server.py
```

The server exposes the static web app and these same-origin endpoints:

- `GET /api/health` — scanner and VM-sandbox availability.
- `POST /api/scan/repository` — streams progress and a report as Server-Sent Events. JSON body: `{"repository":"https://github.com/owner/repo","branch":"optional-branch"}`.
- `POST /api/scan/code` — scans pasted UTF-8 text in memory. JSON body: `{"filename":"sample.ps1","code":"..."}`.

Repository scans use GitHub's public repository metadata API and a bounded archive download, so **only public repositories** are supported and GitHub's API rate limits apply. The scanner checks up to 50 common text/source/config files per repository, skips known generated/dependency folders and binary files, and caps the compressed archive at 24 MB, each file at 500 KB, and total decoded content at 8 MB. The report identifies inspected files and skip counts. These limits and the rule set are in `server.py`.

## Safety and deployment notes

- Submitted source is inspected in memory and is not written to disk by the scanner. Repository metadata is fetched from `api.github.com` and source archives from `codeload.github.com`; the scanner does not accept arbitrary remote URLs or extract archive files to disk.
- The service makes **no VM connection** and has no dynamic-analysis feature. The Windows section in the UI is guidance only; it does not claim that a Windows virtual machine is running or provision one.
- The server has a small per-address request limit but no user authentication. Keep it on a trusted/local network unless you put it behind an authenticated reverse proxy and apply appropriate access controls.
- Do not use a static scan as the sole basis for trusting, blocking, or executing a repository. Review findings and the source code in context.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

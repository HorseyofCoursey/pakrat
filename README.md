# pakrat 🐀

A behavioral supply chain monitor for npm packages.

pakrat watches popular npm packages for suspicious changes — new 
dependencies, new install scripts, and unexpected network calls during 
installation. When something looks wrong, it alerts immediately via Discord.

Built in response to the Axios supply chain attack (March 2026), where 
a compromised maintainer account published malicious versions of one of 
npm's most downloaded packages. The attack added a hidden dependency that 
installed a Remote Access Trojan within 2 seconds of npm install.

## What it catches

- New dependencies added to trusted packages (how the Axios attack worked)
- Install scripts appearing on packages that never had them
- Packages making unexpected DNS lookups during npm install
- Version changes on watched packages
- Dependency removals that could indicate account takeover

## How it works

Every 5 minutes pakrat fetches the latest metadata for watched packages 
and diffs it against a known-good baseline. Any changes trigger a 
behavioral sandbox — an isolated Docker container that installs the 
package while tcpdump monitors every DNS lookup and network connection.

Unexpected connections get flagged immediately via Discord alert.

## Public scan log

`scan-log.json` in this repo updates automatically with every scan. 
Each entry records the package, version, dependency count, and whether 
an install script is present at that point in time. This creates a 
public, auditable history of package behavior that anyone can query.

## Detection layers

**Layer 1 — Manifest diffing**
Compares package.json metadata against a known-good baseline on every
scan. Catches new dependencies, new install scripts, and version changes
the moment they appear on the registry.
**Layer 2 — Behavioral sandbox**
Installs the package in an isolated Docker container with tcpdump
monitoring all network activity. Extracts DNS lookups and flags any
connections to domains outside a known-good allowlist. Per-package
whitelisting handles legitimate false positives like puppeteer downloading
Chromium.
**Layer 3 — Pattern matching**
Secondary signal layer scanning install output for credential access
patterns — SSH directory reads, AWS config access, environment variable
harvesting, base64 encoding.
**Layer 4 — eBPF kernel monitoring**
Attaches bpftrace probes directly to the Linux kernel while the package
installs in a Docker container. Watches every process execution, file
access, and network connection at the syscall level — completely invisible
to anything running inside the container. A RAT cannot detect or evade
kernel-level observation from outside its execution environment.

## CLI usage

Scan any package on demand:
```bash
node pakrat.js scan axios
node pakrat.js scan lodash
node pakrat.js scan express
```

Run a full baseline check across all watched packages:
```bash
node index.js
```

## Self hosted setup

Requirements:
- Ubuntu 24.04 VPS (2GB RAM minimum, 4GB recommended)
- Docker
- Node.js 22+
- tcpdump
- A Discord webhook URL for alerts
- A GitHub token with repo write access for scan log updates

Setup guide coming soon.

## Threat model

pakrat is designed to catch:
- Compromised maintainer accounts publishing malicious versions
- Dependency injection attacks
- Install-time credential theft and exfiltration
- Packages that phone home during installation

pakrat is not designed to catch:
- Runtime attacks that activate after install
- Time-delayed or environment-aware malware
- Attacks on packages outside the watched list

## Roadmap

- [x] Manifest diffing and baseline comparison
- [x] Docker sandbox with tcpdump network monitoring
- [x] DNS-based suspicious activity detection
- [x] Pattern matching on install output
- [x] Per-package whitelist for false positives
- [x] Discord alerting
- [x] CLI scanner
- [x] Public scan log pushing to GitHub
- [x] eBPF kernel-level syscall monitoring
- [ ] VM-based sandbox for evasion-resistant analysis
- [ ] PyPI and RubyGems support
- [ ] Web dashboard and API

## Status

Active. Scanning 50 packages every 5 minutes with four later detection.

---

*pakrat is an early stage open source project. Contributions, 
whitelist additions, and package suggestions welcome.*

# pakrat 🐀

A behavioral supply chain monitor for npm packages.

pakrat watches the most popular npm packages for suspicious changes — 
new dependencies, new install scripts, and unexpected network calls 
during installation. When something looks wrong, it alerts immediately.

## What it catches

- New dependencies added to trusted packages (how the Axios attack worked)
- Install scripts appearing on packages that never had them
- Packages making unexpected network calls during npm install
- Dependency removals that could indicate account takeover

## How it works

Every 5 minutes pakrat fetches the latest metadata for watched packages 
and diffs it against a known-good baseline. Any changes trigger a 
behavioral sandbox — an isolated Docker container that installs the 
package while tcpdump monitors every DNS lookup and network connection.

Unexpected connections get flagged immediately via Discord alert.

## Public scan log

`scan-log.json` in this repo updates automatically with every scan. 
Each entry records the package, version, dependencies, and sandbox 
results at that point in time. This creates a public, auditable history 
of package behavior over time.

## Threat model

pakrat is designed to catch:
- Compromised maintainer accounts publishing malicious versions
- Dependency injection attacks (adding malicious sub-dependencies)
- Install-time credential theft and exfiltration

pakrat is not designed to catch:
- Runtime attacks that activate after install
- Time-delayed or environment-aware malware (future roadmap)
- Attacks on packages outside the watched list

## Roadmap

- [x] Manifest diffing and baseline comparison
- [x] Docker sandbox with network monitoring  
- [x] Discord alerting
- [x] CLI scanner
- [ ] eBPF syscall monitoring
- [ ] VM-based sandbox for evasion-resistant analysis
- [ ] Public API for querying scan history
- [ ] PyPI and RubyGems support

## Status

Active. Scanning every 5 minutes.

---

Built in response to the Axios supply chain attack (March 2026).

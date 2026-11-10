# Private DNS Topologies: Eliminating Split-Brain Resolution Contention in Multi-Spoke Landing Zones

[![Pester Verification](https://img.shields.io/badge/pester-16%2F16%20passing-brightgreen)](tests/PrivateDnsGuard.Tests.ps1)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture Deep-Dive](https://img.shields.io/badge/blog-alerasoul.net-0a1128)](https://alerasoul.net/privatedns-splitbrain-resolution-guard/)

> **Primary Governance Artefact:** Distributed Private DNS Architecture Blueprint & Resolution Test Suite  
> **Accountable Service Owner:** Principal Azure Core Networking & Hybrid Connectivity Architect  
> **Full Architectural Deep-Dive:** [https://alerasoul.net/privatedns-splitbrain-resolution-guard/](https://alerasoul.net/privatedns-splitbrain-resolution-guard/)

---

## Repository Layout (12 Files)

```text
├── .github/workflows/dns-canary.yml
├── .gitignore
├── LICENSE
├── README.md
├── docs/HYBRID-DNS-ARCHITECTURE.md
├── fixtures/spoke-resolution-matrix.json
├── infra/hub-dns-resolver.bicep
├── policies/deny-spoke-privatelink-zone.json
├── policies/dine-central-dns-zone-group.json
├── queries/Dns-NxDomain-Anomalies.kql
├── src/Test-PrivateDnsSplitBrainGuard.ps1
└── tests/PrivateDnsGuard.Tests.ps1
```

## Quickstart & Offline Verification

```powershell
# 1. Execute the primary PowerShell 7 evaluator
pwsh -NoProfile -File ./src/Test-PrivateDnsSplitBrainGuard.ps1

# 2. Run the 16-test Pester verification contract
Invoke-Pester -Path ./tests/PrivateDnsGuard.Tests.ps1 -Output Detailed
```

## License

Released under the [MIT License](LICENSE). Authored by **Shahrad Alerasoul** ([alerasoul.net](https://alerasoul.net)).

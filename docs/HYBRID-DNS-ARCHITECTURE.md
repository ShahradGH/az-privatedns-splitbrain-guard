# Hybrid Private DNS Architecture & L2/L3 Troubleshooting Runbook

## 1. Architectural Invariants

Enterprise Azure Landing Zones must centralise all `privatelink.*` Private DNS Zones inside the Connectivity Hub subscription (`vnet-hub-connectivity`, `172.16.0.0/16`). When application teams deploy Private Endpoints into spoke VNets (`172.17.0.0/16`, `172.18.0.0/16`), any spoke-local `privatelink.*` zone creates a **split-brain resolution trap**:

1. The Azure platform recursive resolver (`168.63.129.16`) evaluates Virtual Network Links attached to the querying workload's VNet **before** forwarding or traversing Hub resolvers.
2. If a spoke VNet is linked to a local, empty `privatelink.blob.core.windows.net` zone, `168.63.129.16` treats that zone as authoritative and returns `NXDOMAIN` (or falls back to the public CNAME `198.51.100.x`), bypassing the central Hub zone entirely.
3. Because Private Endpoint NICs are registered via Azure Policy `DeployIfNotExists` (`policies/dine-central-dns-zone-group.json`) into the Hub zone, the spoke workload fails to reach the RFC 1918 endpoint (`172.17.8.12`).

## 2. Azure DNS Private Resolver Subnet Design

- **Inbound Endpoint Subnet**: `172.16.1.0/28` (minimum `/28` required by `Microsoft.Network/dnsResolvers/inboundEndpoints`). Hosts VIP `172.16.1.4` for on-premises conditional forwarders arriving over ExpressRoute or Site-to-Site VPN.
- **Outbound Endpoint Subnet**: `172.16.1.64/28`. Hosts VIP `172.16.1.68` for DNS Forwarding Rulesets targeting on-premises Active Directory domains (`corp.contoso.local`).
- **Control-Plane Provisioning**: All Private Resolver endpoints, VNet links, and `privateDnsZoneGroups` are governed via PowerShell 7.4+ `Invoke-AzRestMethod` and Azure Policy—eliminating declarative template drift.

## 3. L2 / L3 Operational Runbook

### Symptom A: Workload Resolves Public IP (`198.51.100.x`) Instead of RFC 1918
1. Run `src/Wait-PrivateDnsRecordConvergence.ps1` with `-HubSubscriptionId` and `-SpokeSubscriptionIds` to query Azure Resource Graph (`Microsoft.ResourceGraph/resources`) for rogue `privatelink.*` zones.
2. Execute `ai/Diagnose-PrivateDnsTrace.ps1` with the `Resolve-DnsName` probe output to classify whether the failure is `SHADOW_SPOKE_ZONE`, `MISSING_PRIVATE_DNS_ZONE_GROUP`, or `PUBLIC_FALLBACK_LEAK`.
3. If `SHADOW_SPOKE_ZONE` is confirmed, export any valid A records, unlink and delete the spoke zone, and assign `policies/deny-spoke-privatelink-zone.json` at the Landing Zones management group.

### Symptom B: Intermittent `NXDOMAIN` Immediately After Private Endpoint Deployment
1. `168.63.129.16` caches negative `NXDOMAIN` responses according to the Private DNS Zone SOA minimum TTL.
2. Use `src/Wait-PrivateDnsRecordConvergence.ps1` with exponential backoff (`-InitialBackoffSeconds 2 -MaxAttempts 5`) before running smoke tests.
3. Correlate anomalies in Log Analytics using `queries/Dns-NxDomain-Anomalies.kql`.

### Symptom C: On-Premises Clients Receive `SERVFAIL`
1. Verify ExpressRoute/VPN BGP routes to `172.16.1.4` and check NSG rules allowing UDP/TCP port 53 from RFC 1918 on-premises CIDRs.
2. Run `ai/Diagnose-PrivateDnsTrace.ps1 -OutboundForwarderReachable $false` to validate escalation to NetOps via `graph/Send-NetOpsSplitBrainAlert.ps1`.

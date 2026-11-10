# Test-PrivateDnsSplitBrainGuard.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [PSCustomObject]$DnsProbeResult,
    [Parameter(Mandatory)] [string[]]$SpokeLocalPrivateDnsZones
)

$ErrorActionPreference = 'Stop'

# 1. Hard Veto if any spoke subscription hosts a local privatelink.* zone
$shadowZones = @($SpokeLocalPrivateDnsZones | Where-Object { $_ -match '^privatelink\.' })
if ($shadowZones.Count -gt 0) {
    return [PSCustomObject]@{
        TargetFqdn     = $DnsProbeResult.Fqdn
        Status         = 'VETO_SPOKE_LOCAL_ZONE_SPLIT_BRAIN'
        Healthy        = $false
        ShadowZones    = $shadowZones
        Reason         = "Spoke contains local privatelink zone(s) ($($shadowZones -join ', ')) shadowing central Hub DNS."
    }
}

# 2. Verify resolved IP is strictly within RFC 1918 Private Address Space
$ip = [string]$DnsProbeResult.ResolvedIpAddress
$isRfc1918 = ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')

if (-not $isRfc1918) {
    return [PSCustomObject]@{
        TargetFqdn     = $DnsProbeResult.Fqdn
        ResolvedIp     = $ip
        Status         = 'VETO_PUBLIC_IP_FALLBACK_LEAK'
        Healthy        = $false
        Reason         = "Private Endpoint FQDN '$($DnsProbeResult.Fqdn)' resolved to non-RFC1918 IP '$ip'."
    }
}

return [PSCustomObject]@{
    TargetFqdn     = $DnsProbeResult.Fqdn
    ResolvedIp     = $ip
    Status         = 'COMPLIANT_HUB_PRIVATE_RESOLUTION'
    Healthy        = $true
}

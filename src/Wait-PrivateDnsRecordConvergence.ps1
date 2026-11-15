# Wait-PrivateDnsRecordConvergence.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Fqdn,
    [Parameter(Mandatory)] [string]$HubSubscriptionId,
    [Parameter(Mandatory)] [string[]]$SpokeSubscriptionIds,
    [Parameter()] [int]$MaxAttempts = 5,
    [Parameter()] [int]$InitialBackoffSeconds = 2,
    [Parameter()] [scriptblock]$RestInvoker = $null,
    [Parameter()] [scriptblock]$DnsResolver = $null
)

$ErrorActionPreference = 'Stop'

function Invoke-AzureControlPlane {
    param([string]$Method, [string]$Path, [hashtable]$Body = $null)
    if ($null -ne $RestInvoker) {
        return & $RestInvoker $Method $Path $Body
    }
    $params = @{ Method = $Method; Path = $Path }
    if ($null -ne $Body) {
        $params['Payload'] = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }
    $resp = Invoke-AzRestMethod @params
    if ($resp.StatusCode -ge 400) {
        throw "Azure REST call failed ($($resp.StatusCode)) on $Path : $($resp.Content)"
    }
    return ($resp.Content | ConvertFrom-Json)
}

# Step 1: Query Azure Resource Graph for rogue spoke privatelink.* zones
$allSubs = @($HubSubscriptionId) + @($SpokeSubscriptionIds) | Select-Object -Unique
$argQuery = @"
Resources
| where type =~ 'microsoft.network/privatednszones'
| where name startswith 'privatelink.'
| project id, name, subscriptionId, resourceGroup
"@

$argResult = Invoke-AzureControlPlane -Method 'POST' -Path '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' -Body @{
    subscriptions = $allSubs
    query         = $argQuery
}

$zones = @($argResult.data)
$rogueSpokeZones = @($zones | Where-Object { $_.subscriptionId -ne $HubSubscriptionId })

if ($rogueSpokeZones.Count -gt 0) {
    return [PSCustomObject]@{
        Fqdn             = $Fqdn
        Converged        = $false
        Status           = 'VETO_ROGUE_SPOKE_ZONES_DETECTED'
        RogueZones       = $rogueSpokeZones
        AttemptsUsed     = 0
        ResolvedIp       = $null
    }
}

# Step 2: Poll 168.63.129.16 wire-server with exponential backoff to clear SOA negative cache
$attempt = 0
$delay = $InitialBackoffSeconds
$lastIp = $null

while ($attempt -lt $MaxAttempts) {
    $attempt++
    $probe = if ($null -ne $DnsResolver) {
        & $DnsResolver $Fqdn
    } else {
        Resolve-DnsName -Name $Fqdn -Server '168.63.129.16' -Type A -DnsOnly -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }

    if ($null -ne $probe -and $probe.IPAddress) {
        $lastIp = [string]$probe.IPAddress
        if ($lastIp -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') {
            return [PSCustomObject]@{
                Fqdn         = $Fqdn
                Converged    = $true
                Status       = 'CONVERGED_RFC1918_PRIVATE_IP'
                RogueZones   = @()
                AttemptsUsed = $attempt
                ResolvedIp   = $lastIp
            }
        }
    }

    if ($attempt -lt $MaxAttempts) {
        if ($null -eq $DnsResolver) {
            Start-Sleep -Seconds $delay
        }
        $delay = [Math]::Min($delay * 2, 30)
    }
}

return [PSCustomObject]@{
    Fqdn         = $Fqdn
    Converged    = $false
    Status       = 'TIMEOUT_NEGATIVE_CACHE_OR_PUBLIC_FALLBACK'
    RogueZones   = @()
    AttemptsUsed = $attempt
    ResolvedIp   = $lastIp
}

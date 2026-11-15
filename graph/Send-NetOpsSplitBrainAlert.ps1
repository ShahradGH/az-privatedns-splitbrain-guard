# Send-NetOpsSplitBrainAlert.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [PSCustomObject]$DiagnosisResult,
    [Parameter(Mandatory)] [string]$TeamId,
    [Parameter(Mandatory)] [string]$ChannelId,
    [Parameter()] [string]$IncidentListSiteId = '',
    [Parameter()] [string]$IncidentListId = '',
    [Parameter()] [scriptblock]$GraphInvoker = $null
)

$ErrorActionPreference = 'Stop'

function Invoke-GraphV2 {
    param([string]$Method, [string]$Uri, [hashtable]$Body)
    if ($null -ne $GraphInvoker) {
        return & $GraphInvoker $Method $Uri $Body
    }
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 12) -ContentType 'application/json'
}

if ($DiagnosisResult.DiagnosisCode -eq 'HEALTHY_PRIVATE_RESOLUTION') {
    return [PSCustomObject]@{
        Dispatched = $false
        Reason     = 'Healthy RFC 1918 resolution; no NetOps alert required.'
    }
}

$remediationBullets = if ($DiagnosisResult.RemediationSteps.Count -gt 0) {
    ($DiagnosisResult.RemediationSteps | ForEach-Object { "- $_" }) -join "`n"
} else {
    '- Escalate to NetOps L3 for Hub Private Resolver packet capture.'
}

$adaptiveCard = @{
    type    = 'AdaptiveCard'
    version = '1.5'
    body    = @(
        @{
            type   = 'TextBlock'
            text   = "Private DNS Split-Brain Alert: $($DiagnosisResult.DiagnosisCode)"
            weight = 'Bolder'
            size   = 'Medium'
            color  = 'Attention'
        },
        @{
            type  = 'FactSet'
            facts = @(
                @{ title = 'Target FQDN'; value = [string]$DiagnosisResult.TargetFqdn },
                @{ title = 'Resolved IP'; value = [string]$DiagnosisResult.ResolvedIp },
                @{ title = 'Severity'; value = [string]$DiagnosisResult.Severity },
                @{ title = 'Confidence'; value = [string]$DiagnosisResult.Confidence }
            )
        },
        @{
            type = 'TextBlock'
            text = "Recommended Remediation:`n$remediationBullets"
            wrap = $true
        }
    )
}

$cardAttachmentId = [guid]::NewGuid().ToString()
$teamsPayload = @{
    body        = @{
        contentType = 'html'
        content     = "<attachment id=`"$cardAttachmentId`"></attachment>"
    }
    attachments = @(
        @{
            id          = $cardAttachmentId
            contentType = 'application/vnd.microsoft.card.adaptive'
            content     = ($adaptiveCard | ConvertTo-Json -Depth 10 -Compress)
        }
    )
}

$teamsUri = "https://graph.microsoft.com/v1.0/teams/$TeamId/channels/$ChannelId/messages"
$teamsResponse = Invoke-GraphV2 -Method 'POST' -Uri $teamsUri -Body $teamsPayload

$listResponse = $null
if (-not [string]::IsNullOrWhiteSpace($IncidentListSiteId) -and -not [string]::IsNullOrWhiteSpace($IncidentListId)) {
    $listUri = "https://graph.microsoft.com/v1.0/sites/$IncidentListSiteId/lists/$IncidentListId/items"
    $listPayload = @{
        fields = @{
            Title         = "$($DiagnosisResult.DiagnosisCode): $($DiagnosisResult.TargetFqdn)"
            ResolvedIp    = [string]$DiagnosisResult.ResolvedIp
            Severity      = [string]$DiagnosisResult.Severity
            Confidence    = [double]$DiagnosisResult.Confidence
        }
    }
    $listResponse = Invoke-GraphV2 -Method 'POST' -Uri $listUri -Body $listPayload
}

return [PSCustomObject]@{
    Dispatched        = $true
    TeamsEndpoint     = $teamsUri
    TeamsMessageId    = $teamsResponse.id
    SharePointLogged  = ($null -ne $listResponse)
    DiagnosisCode     = $DiagnosisResult.DiagnosisCode
}

<#
.SYNOPSIS
    Troubleshoots connectivity for a privately deployed Microsoft Foundry (Azure AI Foundry)
    account and its private dependencies (Storage, Cosmos DB, AI Search, Key Vault).

.DESCRIPTION
    Runs a read-only diagnostic sweep and prints a console verdict table.

    Control-plane checks (via Azure CLI):
      * Deployment topology - delegated subnet injection vs Microsoft-managed network vs none
      * publicNetworkAccess, network ACLs, custom subdomain
      * Inbound private endpoints - existence, approval state, DNS zone group, NIC private IP
      * Private DNS zones - zone exists, A record matches the PE NIC IP, VNet links
      * Injected subnet health - delegation, prefix size, NSG, UDR, free IPs
      * Dependency resources discovered from project connections, each checked the same way

    Data-plane checks (from this machine):
      * Which resolver answered, and whether the name resolves to the private
        endpoint or falls through to the public frontend
      * Address is RFC1918 / private, not a public frontend
      * TCP reachability on 443

    DNS VNet-link rule (two-tier):
      PASS       - zone is linked to the injected/delegated VNet
      PASS-NOTE  - zone is linked to a hub/centralized VNet instead
      FAIL       - zone is linked to neither

.PARAMETER ResourceGroup
    Resource group holding the Foundry account.

.PARAMETER AccountName
    Name of the Foundry / Azure AI Services account.

.PARAMETER SubscriptionId
    Optional. Defaults to the current az CLI subscription.

.PARAMETER HubVNetId
    Optional. Resource ID of the known hub / centralized VNet. Supplying it upgrades the
    "centralized VNet" verdict from a guess to a confirmed match.

.PARAMETER SkipClientTests
    Skip the from-this-machine DNS and TCP tests (use when running from a jump box that
    is deliberately outside the private network).

.PARAMETER Detailed
    Print the full detail column without truncation.

.PARAMETER ExportHtml
    Write an HTML report without prompting. Intended for CI and scheduled runs;
    interactive runs are offered the export at the end instead.

.PARAMETER HtmlPath
    Path for the HTML report. Implies -ExportHtml.

.EXAMPLE
    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry

.EXAMPLE
    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry `
        -HubVNetId "/subscriptions/xxx/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub" -Detailed

.EXAMPLE
    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry `
        -SkipClientTests -HtmlPath .\reports\foundry.html
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ResourceGroup,
    [Parameter(Mandatory = $true)][string] $AccountName,
    [string] $SubscriptionId,
    [string] $HubVNetId,
    [switch] $SkipClientTests,
    [switch] $Detailed,
    # Write the HTML report without prompting. Use in CI, scheduled runs, or any
    # non-interactive host; interactive runs get an offer at the end instead.
    [switch] $ExportHtml,
    [string] $HtmlPath
)

$ErrorActionPreference = 'Stop'
$script:Results  = New-Object System.Collections.Generic.List[object]
$script:ApiCS    = '2026-07-01'
$script:ApiNet   = '2024-05-01'
# Sub-resources of a Foundry account trail the account's own API version, so the
# newest account api-version is often rejected for projects/connections. Negotiate.
$script:ApiCandidates = @('2026-07-01', '2026-05-01', '2026-03-01', '2025-12-01', '2025-09-01', '2025-06-01')
$script:ApiUsed  = @{}

# Findings stream to the console as they are discovered - empty section headers
# during a multi-minute run look indistinguishable from a hang.
$script:Live        = $true
$script:CheckWidth  = 42
# Per-resource publicNetworkAccess=Disabled. Drives client-side severity: if the
# service refuses public traffic, resolving to the public frontend is a hard
# failure, not a vantage-point artifact.
$script:PublicDisabled = @{}
# Every private endpoint NIC address discovered on the control plane. Lets the
# client phase distinguish a genuine private endpoint hit from a proxy VIP that
# merely lives in private address space.
$script:KnownPeIps = New-Object System.Collections.Generic.List[string]
$script:LiveDetail  = if ($Detailed) { 4000 } else { 150 }
$script:ColorFor    = @{
    'PASS'      = 'Green'
    'PASS-NOTE' = 'DarkGreen'
    'WARN'      = 'Yellow'
    'FAIL'      = 'Red'
    'INFO'      = 'Gray'
    'SKIP'      = 'DarkGray'
}

#region ---------------------------------------------------------------- helpers

function Write-ResultLine {
    param(
        [Parameter(Mandatory)][pscustomobject] $Row,
        [int] $MaxDetail = 150,
        [string] $Indent = '    ',
        [switch] $ShowArea
    )
    $detail = $Row.Detail
    if ($detail.Length -gt $MaxDetail) { $detail = $detail.Substring(0, $MaxDetail) + '...' }
    $check = if ($Row.Check.Length -gt $script:CheckWidth) {
        $Row.Check.Substring(0, $script:CheckWidth - 1) + '~'
    } else { $Row.Check }

    Write-Host ("$Indent{0,-10}" -f $Row.Status) -ForegroundColor $script:ColorFor[$Row.Status] -NoNewline
    if ($ShowArea) { Write-Host ("{0,-20}" -f $Row.Area) -ForegroundColor DarkCyan -NoNewline }
    Write-Host ("{0,-$($script:CheckWidth)}" -f $check) -ForegroundColor White -NoNewline
    Write-Host $detail -ForegroundColor DarkGray
}

function Add-Result {
    param(
        [Parameter(Mandatory)][string] $Area,
        [Parameter(Mandatory)][string] $Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'PASS-NOTE', 'WARN', 'FAIL', 'INFO', 'SKIP')][string] $Status,
        [string] $Detail = ''
    )
    $row = [pscustomobject]@{
        Area = $Area; Check = $Check; Status = $Status; Detail = $Detail
        # Client findings depend on WHERE the script ran, not on whether the
        # deployment is correct, so they are scored separately and never drive
        # the overall verdict or the exit code.
        Scope = if ($Area -eq 'Client') { 'Client' } else { 'Deployment' }
    }
    $script:Results.Add($row) | Out-Null
    if ($script:Live) { Write-ResultLine -Row $row -MaxDetail $script:LiveDetail }
}

function Write-Phase {
    param([string] $Text)
    Write-Host ''
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "  $('-' * $Text.Length)" -ForegroundColor DarkCyan
}

function Invoke-Az {
    <# Runs an az command, returns parsed JSON or $null. Never throws. #>
    param([Parameter(Mandatory)][string[]] $Args)
    try {
        $raw = & az @Args 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json
    } catch { return $null }
}

function Get-ArmToken {
    <#
      Cache an ARM bearer token. Every `az rest` invocation spawns a Python
      interpreter and costs ~8s; a direct REST call with a cached token costs
      ~1s. Over the 40+ reads a full run makes, that is the difference between
      minutes and seconds.
    #>
    if ($script:ArmToken -and (Get-Date) -lt $script:ArmTokenExpiry) { return $script:ArmToken }
    $t = Invoke-Az @('account', 'get-access-token', '--resource', 'https://management.azure.com', '-o', 'json')
    if (-not $t) { return $null }
    $script:ArmToken = $t.accessToken
    # Refresh well before the real expiry; a long run must not die mid-sweep.
    $script:ArmTokenExpiry = (Get-Date).AddMinutes(30)
    return $script:ArmToken
}

function Invoke-Arm {
    <# GET an ARM resource by id + api-version. Falls back to `az rest` if the
       direct REST path is unavailable for any reason. #>
    param([Parameter(Mandatory)][string] $Id, [Parameter(Mandatory)][string] $ApiVersion)
    $url = "https://management.azure.com$($Id)?api-version=$ApiVersion"

    $tok = Get-ArmToken
    if ($tok) {
        try {
            return Invoke-RestMethod -Uri $url -Method Get -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            # 401 means the cached token went stale - drop it and retry once.
            if ($code -eq 401) {
                $script:ArmToken = $null
                $tok = Get-ArmToken
                if ($tok) {
                    try {
                        return Invoke-RestMethod -Uri $url -Method Get -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop
                    } catch { return $null }
                }
            }
            # 404 / 400 (unsupported api-version) are legitimate "no" answers.
            if ($code -in 400, 403, 404) { return $null }
            return $null
        }
    }
    return Invoke-Az @('rest', '--method', 'get', '--url', $url)
}

function Invoke-ArmNegotiated {
    <#
      GET an ARM resource, trying successive api-versions until one answers.
      Foundry sub-resources (projects, connections) frequently reject the newest
      account api-version with NoRegisteredProviderFound; without this the call
      returns null and the caller silently concludes "nothing there".
    #>
    param([Parameter(Mandatory)][string] $Id, [string] $CacheKey = $Id)
    if ($script:ApiUsed.ContainsKey($CacheKey)) {
        return Invoke-Arm -Id $Id -ApiVersion $script:ApiUsed[$CacheKey]
    }
    foreach ($v in $script:ApiCandidates) {
        $r = Invoke-Arm -Id $Id -ApiVersion $v
        if ($null -ne $r) {
            $script:ApiUsed[$CacheKey] = $v
            return $r
        }
    }
    return $null
}

function Invoke-ArmBatch {
    <#
      Fetch many ARM resources concurrently and return a hashtable of id -> result.
      Runspaces cannot see script-scoped state or functions, so this deliberately
      takes plain data in and hands plain data back; all reporting stays on the
      main thread so live output and ordering are preserved.
    #>
    param(
        [Parameter(Mandatory)][object[]] $Requests,   # @{ Key=..; Id=..; ApiVersion=.. }
        [int] $Throttle = 8
    )
    $out = [hashtable]::Synchronized(@{})
    if (-not $Requests -or $Requests.Count -eq 0) { return $out }

    $tok = Get-ArmToken
    if (-not $tok) {
        foreach ($r in $Requests) { $out[$r.Key] = Invoke-Arm -Id $r.Id -ApiVersion $r.ApiVersion }
        return $out
    }

    $Requests | ForEach-Object -ThrottleLimit $Throttle -Parallel {
        $bag = $using:out
        $t   = $using:tok
        $url = "https://management.azure.com$($_.Id)?api-version=$($_.ApiVersion)"
        try {
            $bag[$_.Key] = Invoke-RestMethod -Uri $url -Method Get -Headers @{ Authorization = "Bearer $t" } -ErrorAction Stop
        } catch {
            $bag[$_.Key] = $null
        }
    }
    return $out
}

function Test-EndpointReachability {
    <#
      Resolve + TCP 443 + TLS issuer for many FQDNs concurrently. Returns plain
      objects; the caller decides severity and emits the findings in order.
      Parallelism matters most here because an unreachable endpoint costs a full
      TCP timeout, and those timeouts otherwise stack up serially.
    #>
    param(
        [Parameter(Mandatory)][object[]] $Items,
        [int] $Throttle = 8
    )
    if (-not $Items -or $Items.Count -eq 0) { return @() }

    # Resolve probe URLs on the main thread - runspaces cannot see script functions.
    $probeUrls = @{}
    foreach ($i in $Items) { $probeUrls[$i.Fqdn] = Get-ServiceProbeUrl -Fqdn $i.Fqdn }

    return $Items | ForEach-Object -ThrottleLimit $Throttle -Parallel {
        $fqdn = $_.Fqdn
        $r = [pscustomobject]@{
            Fqdn = $fqdn; Source = $_.Source
            Addrs = @(); ResolveError = $null
            Tcp = $false; TcpTarget = $null
            TlsIssuer = $null; TlsSubject = $null; TlsSan = $null; TlsError = $null
            HttpStatus = $null; HttpIdHeader = $null; HttpIdValue = $null
            HttpBody = $null; HttpError = $null; HttpUrl = $null
        }
        try {
            $recs = Resolve-DnsName -Name $fqdn -Type A -DnsOnly -ErrorAction Stop
            $r.Addrs = @($recs | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress })
        } catch {
            $r.ResolveError = $_.Exception.Message
            return $r
        }
        if ($r.Addrs.Count -eq 0) { return $r }

        # Prefer a private answer for the transport test when one exists.
        $privAddr = $r.Addrs | Where-Object {
            $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and (
                ($_ -split '\.')[0] -eq '10' -or
                (($_ -split '\.')[0] -eq '172' -and [int]($_ -split '\.')[1] -ge 16 -and [int]($_ -split '\.')[1] -le 31) -or
                (($_ -split '\.')[0] -eq '192' -and ($_ -split '\.')[1] -eq '168') -or
                (($_ -split '\.')[0] -eq '100' -and [int]($_ -split '\.')[1] -ge 64 -and [int]($_ -split '\.')[1] -le 127)
            )
        }
        $ip = if ($privAddr) { $privAddr[0] } else { $r.Addrs[0] }
        $r.TcpTarget = $ip

        # Bounded async connect - Test-NetConnection's own timeout is long and
        # not adjustable, which is exactly what makes a serial sweep drag.
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $iar = $c.BeginConnect($ip, 443, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(5000, $false) -and $c.Connected) {
                $c.EndConnect($iar)
                $r.Tcp = $true
                try {
                    $ssl = [System.Net.Security.SslStream]::new($c.GetStream(), $false, { $true })
                    $ssl.AuthenticateAsClient($fqdn)
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
                    $r.TlsIssuer = $cert.Issuer
                    $r.TlsSubject = $cert.Subject
                    $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
                    $r.TlsSan = if ($san) { $san.Format($false) } else { $cert.Subject }
                    $ssl.Dispose()
                } catch { $r.TlsError = $_.Exception.Message }
            }
            $c.Close()
        } catch { $r.Tcp = $false }

        # --- unauthenticated identity probe -------------------------------
        # The certificate proves we reached *a* genuine Azure frontend, but a
        # wildcard SAN (e.g. *.openai.azure.com) covers every account in the
        # namespace - so it cannot prove we reached THIS account. The service's
        # own error response can: it is signed with a per-request id header that
        # only the real service emits. No credentials are sent and nothing is
        # read; a 401/403 is the expected and desired outcome.
        if ($r.Tcp) {
            $probeUrl = $using:probeUrls
            $url = $probeUrl[$fqdn]
            if ($url) {
                $r.HttpUrl = $url
                try {
                    $resp = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 15 `
                                -SkipHttpErrorCheck -SkipCertificateCheck -ErrorAction Stop
                    $r.HttpStatus = [int]$resp.StatusCode
                    foreach ($h in 'apim-request-id', 'x-ms-request-id', 'x-ms-activity-id', 'request-id') {
                        if ($resp.Headers.ContainsKey($h)) {
                            $r.HttpIdHeader = $h
                            $r.HttpIdValue = ($resp.Headers[$h] | Select-Object -First 1)
                            break
                        }
                    }
                    if ($resp.Content) {
                        $r.HttpBody = [string]$resp.Content
                        if ($r.HttpBody.Length -gt 400) { $r.HttpBody = $r.HttpBody.Substring(0, 400) }
                    }
                } catch {
                    $r.HttpError = $_.Exception.Message
                }
            }
        }
        return $r
    }
}
function Invoke-Graph {
    <#
      Run an Azure Resource Graph KQL query via direct REST and return the rows.
      ARG answers tenant-wide questions in one round trip that would otherwise
      cost dozens of per-resource reads. Note it indexes resources, not child
      record sets - private DNS A records are NOT queryable here and still need
      a direct read.
    #>
    param([Parameter(Mandatory)][string] $Query, [int] $First = 500)
    $tok = Get-ArmToken
    if (-not $tok) { return @() }
    try {
        $body = @{ query = $Query; options = @{ '$top' = $First } }
        if ($script:SubScope -and $script:SubScope.Count -gt 0) {
            $body['subscriptions'] = @($script:SubScope)
        }
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' `
            -Headers @{ Authorization = "Bearer $tok" } `
            -ContentType 'application/json' `
            -Body ($body | ConvertTo-Json -Depth 6) -ErrorAction Stop
        if ($resp -and $resp.data) { return ConvertTo-Array $resp.data }
    } catch { return @() }
    return @()
}

function Get-ServiceProbeUrl {
    <#
      An unauthenticated URL per service type that provokes a response the real
      service signs with an identifying header. No credentials are ever sent and
      no data is read - the point is purely "who answered".
    #>
    param([string] $Fqdn)
    switch -Regex ($Fqdn) {
        '\.openai\.azure\.com$'          { return "https://$Fqdn/openai/models?api-version=2024-10-21" }
        '\.services\.ai\.azure\.com$'    { return "https://$Fqdn/openai/models?api-version=2024-10-21" }
        '\.cognitiveservices\.azure\.com$' { return "https://$Fqdn/openai/models?api-version=2024-10-21" }
        '\.blob\.core\.windows\.net$'    { return "https://$Fqdn/?comp=list" }
        '\.file\.core\.windows\.net$'    { return "https://$Fqdn/?comp=list" }
        '\.documents\.azure\.com$'       { return "https://$Fqdn/" }
        '\.search\.windows\.net$'        { return "https://$Fqdn/indexes?api-version=2023-11-01" }
        '\.vaultcore\.azure\.net$'       { return "https://$Fqdn/secrets?api-version=7.4" }
        default                          { return "https://$Fqdn/" }
    }
}

function Test-CertNameMatch {
    <#
      Does the presented certificate actually vouch for the FQDN we asked for?
      Through a proxy or load-balancer VIP this is the strongest client-side
      evidence that traffic reached the intended backend: the address tells you
      nothing, but the certificate identity does.
    #>
    param([string] $Fqdn, [string] $SanText, [string] $Subject)
    if (-not $Fqdn) { return $null }

    $names = @()
    if ($SanText) {
        foreach ($m in [regex]::Matches($SanText, 'DNS Name=([^\s,]+)')) {
            $names += $m.Groups[1].Value.Trim()
        }
    }
    if (-not $names -and $Subject -match 'CN=([^,]+)') { $names += $Matches[1].Trim() }
    if (-not $names) { return $null }

    foreach ($n in $names) {
        if ($n -ieq $Fqdn) { return $true }
        if ($n.StartsWith('*.')) {
            $suffix = $n.Substring(1)                     # ".openai.azure.com"
            $hostPart = $Fqdn.Substring(0, [Math]::Max(0, $Fqdn.Length - $suffix.Length))
            if ($Fqdn -like "*$suffix" -and $hostPart -and $hostPart -notmatch '\.') { return $true }
        }
    }
    return $false
}

function Get-IdSegment {
    <# Pulls a named segment out of an ARM resource id, e.g. 'virtualNetworks'. #>
    param([string] $Id, [string] $Segment)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    $parts = $Id.Trim('/') -split '/'
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if ($parts[$i] -ieq $Segment) { return $parts[$i + 1] }
    }
    return $null
}

function Get-VNetIdFromSubnetId {
    param([string] $SubnetId)
    if ([string]::IsNullOrWhiteSpace($SubnetId)) { return $null }
    if ($SubnetId -match '^(?<v>.+/virtualNetworks/[^/]+)/subnets/') { return $Matches['v'] }
    return $null
}

function Test-PrivateIPv4 {
    param([string] $Address)
    if ($Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $o = $Address -split '\.' | ForEach-Object { [int]$_ }
    if ($o[0] -eq 10) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $true }   # CGNAT, used by some hubs
    return $false
}

function Get-PrefixSize {
    param([string] $Prefix)
    if ($Prefix -match '/(\d+)$') { return [int]$Matches[1] }
    return $null
}

function ConvertTo-Array {
    <# Normalises $null / single object / array into an array. #>
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return $Value }
    return @($Value)
}

#endregion

#region ---------------------------------------------------- 0. preflight / context

Write-Host ''
Write-Host '  Microsoft Foundry - private connectivity diagnostics' -ForegroundColor White
Write-Host "  account: $AccountName   rg: $ResourceGroup   $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host ''
    Write-Host '  FATAL: Azure CLI (az) not found on PATH.' -ForegroundColor Red
    Write-Host '  Install it, then re-run:' -ForegroundColor Yellow
    Write-Host '      winget install --exact --id Microsoft.AzureCLI' -ForegroundColor Gray
    Write-Host '      https://aka.ms/InstallAzureCLIWindows' -ForegroundColor Gray
    Write-Host ''
    exit 2
}
$azVer = Invoke-Az @('version', '-o', 'json')
Add-Result 'Prereq' 'Azure CLI' 'PASS' "v$($azVer.'azure-cli')"

# PowerShell 7+ is required for ForEach-Object -Parallel, which the ARM and
# endpoint probes rely on.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host ''
    Write-Host "  FATAL: PowerShell 7+ required (found $($PSVersionTable.PSVersion)). Parallel execution is unavailable on Windows PowerShell 5.1." -ForegroundColor Red
    Write-Host '      winget install --exact --id Microsoft.PowerShell' -ForegroundColor Gray
    Write-Host ''
    exit 2
}
Add-Result 'Prereq' 'PowerShell' 'PASS' "$($PSVersionTable.PSVersion) (parallel execution available)"

# The resource-graph extension makes tenant-wide private endpoint and DNS link
# discovery a single query instead of dozens of per-resource reads. Install it
# automatically rather than silently degrading to the slow path.
$argExt = Invoke-Az @('extension', 'show', '--name', 'resource-graph', '-o', 'json')
if (-not $argExt) {
    Write-Host '  Installing the Azure CLI resource-graph extension (one time)...' -ForegroundColor Yellow
    & az extension add --name resource-graph --only-show-errors 2>$null | Out-Null
    $argExt = Invoke-Az @('extension', 'show', '--name', 'resource-graph', '-o', 'json')
    if ($argExt) {
        Add-Result 'Prereq' 'resource-graph extension' 'PASS' "Installed v$($argExt.version)."
    } else {
        Add-Result 'Prereq' 'resource-graph extension' 'WARN' 'Could not install it. The script still works via direct REST and per-resource reads, but cross-subscription discovery will be slower and narrower.'
    }
} else {
    Add-Result 'Prereq' 'resource-graph extension' 'PASS' "v$($argExt.version)"
}

# --- authentication -----------------------------------------------------------
if ($SubscriptionId) {
    & az account set --subscription $SubscriptionId 2>$null | Out-Null
}
$ctx = Invoke-Az @('account', 'show', '-o', 'json')
if (-not $ctx) {
    Write-Host ''
    Write-Host '  Not signed in to Azure. Starting device code sign-in...' -ForegroundColor Yellow
    Write-Host '  Open the URL shown below and enter the code to continue.' -ForegroundColor Yellow
    Write-Host ''
    # Device code works over SSH, in containers, and on hosts with no browser -
    # exactly where a private-network diagnostic tends to be run.
    & az login --use-device-code --only-show-errors | Out-Null
    Write-Host ''
    if ($SubscriptionId) {
        & az account set --subscription $SubscriptionId 2>$null | Out-Null
    }
    $ctx = Invoke-Az @('account', 'show', '-o', 'json')
    if (-not $ctx) {
        Write-Host '  FATAL: sign-in did not complete. Run "az login --use-device-code" manually, then re-run.' -ForegroundColor Red
        Write-Host ''
        exit 2
    }
    Add-Result 'Prereq' 'Sign-in' 'PASS' "Signed in interactively as $($ctx.user.name)."
}
$SubscriptionId = $ctx.id
$idLabel = if ($ctx.user.type -eq 'servicePrincipal') {
    "service principal $($ctx.user.name)"
} else {
    $ctx.user.name
}
Add-Result 'Context' 'Azure CLI session' 'INFO' "$($ctx.name) [$($ctx.id)] as $idLabel"

# Fail fast if the token cannot be minted - every read below depends on it.
if (-not (Get-ArmToken)) {
    Write-Host ''
    Write-Host '  FATAL: could not acquire an ARM access token. Try: az login --use-device-code' -ForegroundColor Red
    Write-Host ''
    exit 2
}

# Pin the subscription set used for cross-subscription lookups. Private DNS zones
# routinely live in a hub subscription, and the ambient CLI context can be changed
# by another process mid-run - which silently turns "zone not found" into a false
# finding. Resolve the list once and pass it explicitly on every search.
$subsRaw = Invoke-Az @('account', 'list', '--query', "[?state=='Enabled'].id", '-o', 'json')
$script:SubScope = @(ConvertTo-Array $subsRaw)
if ($script:SubScope -notcontains $SubscriptionId) { $script:SubScope += $SubscriptionId }
Add-Result 'Context' 'Search scope' 'INFO' "$($script:SubScope.Count) enabled subscription(s) searched for private DNS zones."

#endregion

#region ------------------------------------------------- 1. account + topology

Write-Phase '1. Foundry account and deployment topology'

$acctId  = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.CognitiveServices/accounts/$AccountName"
$account = Invoke-Arm -Id $acctId -ApiVersion $script:ApiCS

if (-not $account) {
    Add-Result 'Account' 'Resolve account' 'FAIL' "Not found or no access: $acctId"
    Write-Host ''
    Write-Host '  FATAL: cannot read the Foundry account. Check name, RG, subscription and RBAC.' -ForegroundColor Red
    Write-Host ''
    exit 1
}

$props    = $account.properties
$location = $account.location
Add-Result 'Account' 'Resolve account' 'PASS' "kind=$($account.kind) sku=$($account.sku.name) region=$location"

if ($props.provisioningState -eq 'Succeeded') {
    Add-Result 'Account' 'Provisioning state' 'PASS' $props.provisioningState
} else {
    Add-Result 'Account' 'Provisioning state' 'FAIL' "$($props.provisioningState) - resource is not healthy; fix this before chasing network issues"
}

# --- topology classification -------------------------------------------------
$injections     = ConvertTo-Array $props.networkInjections
$agentInjection = $injections | Where-Object { $_.scenario -and $_.scenario -ne 'none' } | Select-Object -First 1
$injectedSubnetId = $null
$injectedVNetId   = $null
$topology         = 'none'

if ($agentInjection) {
    if ($agentInjection.useMicrosoftManagedNetwork -eq $true) {
        $topology = 'managed-network'
        Add-Result 'Topology' 'Deployment type' 'INFO' "Microsoft-managed network (scenario=$($agentInjection.scenario)). Outbound is Microsoft-managed; there is no customer subnet to inspect."
    } elseif ($agentInjection.subnetArmId) {
        $topology         = 'delegated-subnet'
        $injectedSubnetId = $agentInjection.subnetArmId
        $injectedVNetId   = Get-VNetIdFromSubnetId $injectedSubnetId
        Add-Result 'Topology' 'Deployment type' 'PASS' "Delegated subnet injection (scenario=$($agentInjection.scenario)) -> $(Get-IdSegment $injectedSubnetId 'virtualNetworks')/$(Get-IdSegment $injectedSubnetId 'subnets')"
    } else {
        $topology = 'injection-incomplete'
        Add-Result 'Topology' 'Deployment type' 'FAIL' "networkInjections present with scenario=$($agentInjection.scenario) but neither subnetArmId nor useMicrosoftManagedNetwork is set."
    }
} else {
    Add-Result 'Topology' 'Deployment type' 'INFO' 'No VNet injection configured. Inbound private endpoints may still apply; agent outbound traffic is not injected into a customer VNet.'
}

#endregion

#region -------------------------------------------- 2. control-plane exposure

Write-Phase '2. Control-plane network configuration'

$pna = $props.publicNetworkAccess
switch ($pna) {
    'Disabled' {
        $script:PublicDisabled[$AccountName] = $true
        Add-Result 'Control plane' 'publicNetworkAccess' 'PASS' 'Disabled - private-only, as expected for a private deployment.'
    }
    'Enabled'  { Add-Result 'Control plane' 'publicNetworkAccess' 'WARN' 'Enabled - the public endpoint still answers. Traffic may silently be flowing over the internet instead of your private endpoint.' }
    default    { Add-Result 'Control plane' 'publicNetworkAccess' 'INFO' "Value: $pna" }
}

$acls = $props.networkAcls
if ($acls) {
    $ipRules     = ConvertTo-Array $acls.ipRules
    $vnetRules   = ConvertTo-Array $acls.virtualNetworkRules
    Add-Result 'Control plane' 'Network ACLs' 'INFO' "defaultAction=$($acls.defaultAction) ipRules=$($ipRules.Count) vnetRules=$($vnetRules.Count)"
    if ($acls.defaultAction -eq 'Allow' -and $pna -eq 'Enabled') {
        Add-Result 'Control plane' 'ACL default action' 'WARN' 'defaultAction=Allow with public access enabled - the account is effectively open.'
    }
} else {
    Add-Result 'Control plane' 'Network ACLs' 'INFO' 'No networkAcls object set.'
}

if ($props.customSubDomainName) {
    Add-Result 'Control plane' 'Custom subdomain' 'PASS' $props.customSubDomainName
} else {
    Add-Result 'Control plane' 'Custom subdomain' 'FAIL' 'No custom subdomain. Private endpoints and Entra ID token auth both require one; the regional shared endpoint cannot be reached privately.'
}

$endpoints = @()
if ($props.endpoint) { $endpoints += $props.endpoint }
if ($props.endpoints) {
    foreach ($p in $props.endpoints.PSObject.Properties) {
        if ($p.Value -and $p.Value -notin $endpoints) { $endpoints += $p.Value }
    }
}
$fqdns = @()
foreach ($e in $endpoints) {
    try { $u = [uri]$e; if ($u.Host) { $fqdns += $u.Host } } catch { }
}
$fqdns = $fqdns | Sort-Object -Unique
Add-Result 'Control plane' 'Data-plane FQDNs' 'INFO' ($fqdns -join ', ')

#endregion

#region --------------------------------- 3. build the resource inventory

Write-Phase '3. Dependency discovery (project connections)'

# Each target: Name / Type / ResourceId / Zones (required private DNS zones)
$targets = New-Object System.Collections.Generic.List[object]
$targets.Add([pscustomobject]@{
    Name  = $AccountName
    Type  = 'Foundry account'
    Id    = $acctId
    # DNS label the private endpoint A records are registered under
    Label = if ($props.customSubDomainName) { $props.customSubDomainName } else { $AccountName }
    Zones = @('privatelink.services.ai.azure.com', 'privatelink.openai.azure.com', 'privatelink.cognitiveservices.azure.com')
    Area  = "Foundry: $AccountName"
}) | Out-Null

$zoneMap = @{
    'Microsoft.Storage/storageAccounts'      = @('privatelink.blob.core.windows.net', 'privatelink.file.core.windows.net')
    'Microsoft.DocumentDB/databaseAccounts'  = @('privatelink.documents.azure.com')
    'Microsoft.Search/searchServices'        = @('privatelink.search.windows.net')
    'Microsoft.KeyVault/vaults'              = @('privatelink.vaultcore.azure.net')
}
# Human-readable service names so each report section says what the resource is,
# not just what it is called.
$friendlyType = @{
    'Foundry account'                        = 'Foundry'
    'Microsoft.Storage/storageAccounts'      = 'Storage'
    'Microsoft.DocumentDB/databaseAccounts'  = 'Cosmos DB'
    'Microsoft.Search/searchServices'        = 'AI Search'
    'Microsoft.KeyVault/vaults'              = 'Key Vault'
}
$typeApi = @{
    'Microsoft.Storage/storageAccounts'      = '2023-05-01'
    'Microsoft.DocumentDB/databaseAccounts'  = '2024-11-15'
    'Microsoft.Search/searchServices'        = '2023-11-01'
    'Microsoft.KeyVault/vaults'              = '2023-07-01'
}
# A resource only needs the zone matching the sub-resource its private endpoint
# actually targets. Checking every theoretically-possible zone produces false
# failures (e.g. flagging a missing file-share record on a blob-only account).
$groupIdZone = @{
    'blob'          = 'privatelink.blob.core.windows.net'
    'file'          = 'privatelink.file.core.windows.net'
    'table'         = 'privatelink.table.core.windows.net'
    'queue'         = 'privatelink.queue.core.windows.net'
    'dfs'           = 'privatelink.dfs.core.windows.net'
    'web'           = 'privatelink.web.core.windows.net'
    'sql'           = 'privatelink.documents.azure.com'
    'mongodb'       = 'privatelink.mongo.cosmos.azure.com'
    'cassandra'     = 'privatelink.cassandra.cosmos.azure.com'
    'gremlin'       = 'privatelink.gremlin.cosmos.azure.com'
    'searchservice' = 'privatelink.search.windows.net'
    'vault'         = 'privatelink.vaultcore.azure.net'
}

$projects = Invoke-ArmNegotiated -Id "$acctId/projects" -CacheKey 'projects'
if ($null -eq $projects) {
    Add-Result 'Dependencies' 'Enumerate projects' 'FAIL' "Could not list projects under the account on any of: $($script:ApiCandidates -join ', '). Dependency checks below are incomplete - do not read the absence of findings as a clean bill of health."
}
$projList = ConvertTo-Array $projects.value
Add-Result 'Dependencies' 'Projects found' 'INFO' (($projList | ForEach-Object { ($_.name -split '/')[-1] }) -join ', ')

$seen        = New-Object System.Collections.Generic.HashSet[string]
$otherConns  = New-Object System.Collections.Generic.List[string]
$connReadOk  = $false

foreach ($proj in $projList) {
    # $proj.name is returned fully qualified ("account/project"), so build the
    # connections URL from the project's own resource id rather than its name.
    $projLeaf = ($proj.name -split '/')[-1]
    $projId   = if ($proj.id) { $proj.id } else { "$acctId/projects/$projLeaf" }

    $conns = Invoke-ArmNegotiated -Id "$projId/connections" -CacheKey 'connections'
    if ($null -eq $conns) {
        Add-Result 'Dependencies' "Read connections [$projLeaf]" 'FAIL' "Could not list project connections on any of: $($script:ApiCandidates -join ', '). Private dependencies cannot be enumerated."
        continue
    }
    $connReadOk = $true

    foreach ($c in (ConvertTo-Array $conns.value)) {
        $resId = $null
        if ($c.properties.metadata) {
            foreach ($mp in $c.properties.metadata.PSObject.Properties) {
                if ($mp.Name -match '^resourceid$' -and $mp.Value -match '^/subscriptions/') {
                    $resId = $mp.Value; break
                }
            }
        }
        if (-not $resId -and $c.properties.target -match '^/subscriptions/') { $resId = $c.properties.target }
        if (-not $resId) {
            if ($c.properties.category) { $otherConns.Add("$($c.name) [$($c.properties.category)]") | Out-Null }
            continue
        }

        $provider = $null
        if ($resId -match '/providers/(?<p>[^/]+/[^/]+)/') { $provider = $Matches['p'] }
        if (-not $provider -or -not $zoneMap.ContainsKey($provider)) {
            $otherConns.Add("$($c.name) [$($c.properties.category)]") | Out-Null
            continue
        }
        if (-not $seen.Add($resId.ToLower())) { continue }

        $targets.Add([pscustomobject]@{
            Name  = ($resId -split '/')[-1]
            Type  = $provider
            Id    = $resId
            Label = ($resId -split '/')[-1]
            Zones = $zoneMap[$provider]
            Area  = "$($friendlyType[$provider]): $(($resId -split '/')[-1])"
        }) | Out-Null
    }
}

if ($script:ApiUsed['connections']) {
    Add-Result 'Dependencies' 'Connections API version' 'INFO' $script:ApiUsed['connections']
}

$depCount = $targets.Count - 1
if ($depCount -gt 0) {
    Add-Result 'Dependencies' 'Private dependencies discovered' 'PASS' (($targets | Select-Object -Skip 1 | ForEach-Object { "$($_.Name) ($(($_.Type -split '/')[-1]))" }) -join ', ')
} elseif ($connReadOk) {
    Add-Result 'Dependencies' 'Private dependencies discovered' 'WARN' 'Connections were readable but none resolved to Storage / Cosmos DB / AI Search / Key Vault. This account appears to use Microsoft-managed dependencies rather than BYO resources.'
}

if ($otherConns.Count -gt 0) {
    Add-Result 'Dependencies' 'Other connections (not checked)' 'INFO' "$($otherConns -join ', '). These are not standard private-link dependency types; App Insights/Log Analytics private access requires an Azure Monitor Private Link Scope (AMPLS), which this script does not evaluate."
}

#endregion

#region --------------------- 4. private endpoints + DNS per resource

Write-Phase '4. Private endpoints and private DNS'

# Cache of zone name -> zone objects found anywhere we can see
$zoneCache = @{}

function Find-PrivateDnsZone {
    param([string] $ZoneName)
    if ($zoneCache.ContainsKey($ZoneName)) { return $zoneCache[$ZoneName] }

    $rows = Invoke-Graph -Query @"
Resources
| where type =~ 'microsoft.network/privatednszones' and name =~ '$ZoneName'
| project id, name, subscriptionId, resourceGroup
"@ -First 50

    # Resource Graph can lag or be throttled; fall back to a direct list so an empty
    # ARG result never masquerades as "the zone does not exist". Bounded to the
    # account's own subscription plus an explicit hub, since a serial sweep of every
    # accessible subscription would be pathologically slow in large tenants.
    if (-not $rows -or $rows.Count -eq 0) {
        $fallbackSubs = @($SubscriptionId)
        if ($HubVNetId -and $HubVNetId -match '^/subscriptions/(?<s>[^/]+)/') {
            if ($Matches['s'] -ne $SubscriptionId) { $fallbackSubs += $Matches['s'] }
        }
        foreach ($s in $fallbackSubs) {
            $local = Invoke-Az @('network', 'private-dns', 'zone', 'list', '--subscription', $s,
                                 '--query', "[?name=='$ZoneName'].{id:id,name:name,resourceGroup:resourceGroup}", '-o', 'json')
            $rows += ConvertTo-Array $local
        }
    }
    $zoneCache[$ZoneName] = $rows
    return $rows
}

function Get-ZoneLinkIndex {
    <#
      Pull every private DNS zone VNet link in scope in ONE Resource Graph query
      and index it by zone id. Replaces an N-round-trip walk with a single call.
    #>
    if ($null -ne $script:ZoneLinkIndex) { return $script:ZoneLinkIndex }
    $idx = @{}
    $rows = Invoke-Graph -Query @"
Resources
| where type =~ 'microsoft.network/privatednszones/virtualnetworklinks'
| extend zoneId = strcat_array(array_slice(split(id, '/'), 0, 8), '/')
| project linkName = name, zoneId,
          vnetId = tostring(properties.virtualNetwork.id),
          registration = tobool(properties.registrationEnabled)
"@ -First 1000
    foreach ($r in $rows) {
        if (-not $r.zoneId) { continue }
        $k = $r.zoneId.ToLower()
        if (-not $idx.ContainsKey($k)) { $idx[$k] = New-Object System.Collections.Generic.List[object] }
        $idx[$k].Add($r) | Out-Null
    }
    $script:ZoneLinkIndex = $idx
    return $idx
}

function Test-ZoneVNetLinks {
    <# Two-tier verdict: injected VNet = PASS, hub/central VNet = PASS-NOTE, neither = FAIL. #>
    param([string] $ZoneId, [string] $ZoneName, [string] $Area)

    # Prefer the single-query Resource Graph index; fall back to a per-zone read
    # when ARG is unavailable or has not yet indexed a freshly created link.
    $linkedVNetIds = @()
    $names         = ''
    $regEnabled    = @()

    $idx = Get-ZoneLinkIndex
    $hit = $idx[$ZoneId.ToLower()]
    if ($hit -and $hit.Count -gt 0) {
        $linkedVNetIds = $hit | ForEach-Object { $_.vnetId } | Where-Object { $_ }
        $names = ($hit | ForEach-Object { "$($_.linkName)->$(Get-IdSegment $_.vnetId 'virtualNetworks')" }) -join ', '
        $regEnabled = $hit | Where-Object { $_.registration -eq $true } | ForEach-Object { $_.linkName }
    } else {
        $links = Invoke-Arm -Id "$ZoneId/virtualNetworkLinks" -ApiVersion '2020-06-01'
        $linkList = ConvertTo-Array $links.value
        if ($linkList.Count -eq 0) {
            Add-Result $Area "Zone links: $($ZoneName -replace '^privatelink\.','')" 'FAIL' 'Zone has no virtual network links at all. Nothing can resolve it.'
            return
        }
        $linkedVNetIds = $linkList | ForEach-Object { $_.properties.virtualNetwork.id } | Where-Object { $_ }
        $names = ($linkList | ForEach-Object { "$($_.name)->$(Get-IdSegment $_.properties.virtualNetwork.id 'virtualNetworks')" }) -join ', '
        $regEnabled = $linkList | Where-Object { $_.properties.registrationEnabled -eq $true } | ForEach-Object { $_.name }
    }

    if (-not $linkedVNetIds -or $linkedVNetIds.Count -eq 0) {
        Add-Result $Area "Zone links: $($ZoneName -replace '^privatelink\.','')" 'FAIL' 'Zone has no virtual network links at all. Nothing can resolve it.'
        return
    }

    $matchInjected = $false
    if ($injectedVNetId) {
        $matchInjected = [bool]($linkedVNetIds | Where-Object { $_ -ieq $injectedVNetId })
    }
    $matchHub = $false
    if ($HubVNetId) {
        $matchHub = [bool]($linkedVNetIds | Where-Object { $_ -ieq $HubVNetId })
    }

    if ($matchInjected) {
        Add-Result $Area "Zone links: $($ZoneName -replace '^privatelink\.','')" 'PASS' "Linked to the injected VNet ($(Get-IdSegment $injectedVNetId 'virtualNetworks')). Links: $names"
    } elseif ($matchHub) {
        Add-Result $Area "Zone links: $($ZoneName -replace '^privatelink\.','')" 'PASS-NOTE' "Linked to the supplied hub VNet ($(Get-IdSegment $HubVNetId 'virtualNetworks')) but NOT to the injected VNet. Valid only if the injected VNet peers to the hub AND uses the hub resolver / DNS servers. Links: $names"
    } elseif ($injectedVNetId -or $HubVNetId) {
        Add-Result $Area "Zone links: $($ZoneName -replace '^privatelink\.','')" 'PASS-NOTE' "Linked to a centralized/other VNet, not the injected VNet. Confirm that VNet is your hub resolver and that the injected VNet forwards to it. Links: $names"
    } else {
        Add-Result $Area "Zone links: $($ZoneName -replace '^privatelink\.','')" 'INFO' "No injected VNet to compare against. Links: $names"
    }

    if ($regEnabled -and $regEnabled.Count -gt 0) {
        Add-Result $Area "Zone auto-registration: $($ZoneName -replace '^privatelink\.','')" 'WARN' "registrationEnabled=true on: $($regEnabled -join ', '). Private-link zones should have auto-registration off; it can overwrite private endpoint A records."
    }
}

function Test-ResourcePrivateLink {
    param([pscustomobject] $Target)

    $area  = if ($Target.Area) { $Target.Area } else { $Target.Name }
    $short = ($Target.Type -split '/')[-1]

    $res = Invoke-Arm -Id $Target.Id -ApiVersion ($typeApi[$Target.Type] ?? $script:ApiCS)
    if (-not $res) {
        Add-Result $area "Read $short" 'WARN' "Cannot read $($Target.Id) - likely cross-subscription or missing Reader. Skipping its checks."
        return
    }

    # public exposure on the dependency
    $depPna = $res.properties.publicNetworkAccess
    if ($depPna) {
        if ($depPna -match 'Disabled|Deny|SecuredByPerimeter') {
            $script:PublicDisabled[$Target.Name] = $true
            Add-Result $area 'publicNetworkAccess' 'PASS' $depPna
        } else {
            Add-Result $area 'publicNetworkAccess' 'WARN' "$depPna - dependency still reachable publicly; a working app here does not prove private connectivity works."
        }
    }

    # private endpoint connections on the resource
    $pecs = ConvertTo-Array $res.properties.privateEndpointConnections
    if ($pecs.Count -eq 0) {
        Add-Result $area 'Private endpoints' 'FAIL' "No private endpoint connections on this $short. With public access locked down, Foundry cannot reach it."
        return
    }

    $approved = @()
    foreach ($pec in $pecs) {
        $state = $pec.properties.privateLinkServiceConnectionState.status
        $peId  = $pec.properties.privateEndpoint.id
        $peNm  = if ($peId) { ($peId -split '/')[-1] } else { $pec.name }
        $sfx   = if ($pecs.Count -gt 1) { " [$peNm]" } else { '' }
        if ($state -ieq 'Approved') {
            $approved += $pec
        } else {
            Add-Result $area "PE connection$sfx" 'FAIL' "State=$state - $($pec.properties.privateLinkServiceConnectionState.description). Traffic will be rejected until approved."
        }
    }
    if ($approved.Count -gt 0) {
        Add-Result $area 'Private endpoints' 'PASS' "$($approved.Count) approved connection(s)."
    }

    # Which sub-resources are actually private-linked? Only their zones matter.
    # groupIds are carried on the private endpoint's own connection objects; the
    # resource-side privateEndpointConnections usually omit them, so seed from the
    # PEC here and let the private endpoint walk below fill in the rest.
    $groupIds = @()
    foreach ($pec in $pecs) { $groupIds += (ConvertTo-Array $pec.properties.groupIds) }

    # ---- walk each approved PE: placement, NIC IPs, zone group -------------
    $allExpectedIps = New-Object System.Collections.Generic.List[string]
    $fqdnIpMap      = @{}
    $wiredZoneIds   = New-Object System.Collections.Generic.List[string]

    foreach ($pec in $approved) {
        $peId = $pec.properties.privateEndpoint.id
        if (-not $peId) { continue }
        $peNm = ($peId -split '/')[-1]
        # Only disambiguate labels with the endpoint name when there is more than
        # one; otherwise it is redundant and eats column width.
        $peSfx = if ($approved.Count -gt 1) { " [$peNm]" } else { '' }
        $pe   = Invoke-Arm -Id $peId -ApiVersion $script:ApiNet
        if (-not $pe) {
            Add-Result $area "PE detail$peSfx" 'WARN' 'Private endpoint object not readable (different subscription?).'
            continue
        }

        # where does the PE live
        $peSubnet = $pe.properties.subnet.id
        Add-Result $area "PE placement$peSfx" 'INFO' "$(Get-IdSegment $peSubnet 'virtualNetworks')/$(Get-IdSegment $peSubnet 'subnets')"

        # exact FQDN -> IP mapping, when the platform published one
        foreach ($cfg in (ConvertTo-Array $pe.properties.customDnsConfigs)) {
            foreach ($ip in (ConvertTo-Array $cfg.ipAddresses)) {
                if ($cfg.fqdn) { $fqdnIpMap[$cfg.fqdn] = $ip }
                if ($ip -and -not $allExpectedIps.Contains($ip)) { $allExpectedIps.Add($ip) | Out-Null }
            }
        }
        # the authoritative groupIds live here
        foreach ($plsc in (ConvertTo-Array $pe.properties.privateLinkServiceConnections)) {
            $groupIds += (ConvertTo-Array $plsc.properties.groupIds)
        }
        foreach ($plsc in (ConvertTo-Array $pe.properties.manualPrivateLinkServiceConnections)) {
            $groupIds += (ConvertTo-Array $plsc.properties.groupIds)
        }
        # always read the NICs too - customDnsConfigs is frequently empty
        foreach ($nicRef in (ConvertTo-Array $pe.properties.networkInterfaces)) {
            $nic = Invoke-Arm -Id $nicRef.id -ApiVersion $script:ApiNet
            foreach ($ipc in (ConvertTo-Array $nic.properties.ipConfigurations)) {
                $ip = $ipc.properties.privateIPAddress
                if ($ip -and -not $allExpectedIps.Contains($ip)) { $allExpectedIps.Add($ip) | Out-Null }
            }
        }

        if ($allExpectedIps.Count -eq 0) {
            Add-Result $area "PE NIC addresses$peSfx" 'FAIL' 'Private endpoint has no private IP addresses. The endpoint is not functional.'
        } else {
            $nonPriv = $allExpectedIps | Where-Object { -not (Test-PrivateIPv4 $_) }
            $status  = if ($nonPriv) { 'WARN' } else { 'PASS' }
            Add-Result $area "PE NIC addresses$peSfx" $status ($allExpectedIps -join ', ')
            # Publish for the client phase so it can tell a real private endpoint
            # address apart from a proxy/load-balancer VIP that merely looks private.
            foreach ($eip in $allExpectedIps) {
                if (-not $script:KnownPeIps.Contains($eip)) { $script:KnownPeIps.Add($eip) | Out-Null }
            }
        }

        # Read the DNS zone group purely to learn which zones this endpoint is
        # wired to - those get their A records validated below. The presence or
        # absence of a zone group is not itself reported: hand-managed and
        # IaC-managed records resolve exactly as well, so it is not a finding.
        $zgs = Invoke-Arm -Id "$peId/privateDnsZoneGroups" -ApiVersion $script:ApiNet
        foreach ($zg in (ConvertTo-Array $zgs.value)) {
            foreach ($cfg in (ConvertTo-Array $zg.properties.privateDnsZoneConfigs)) {
                if ($cfg.privateDnsZoneId -and -not $wiredZoneIds.Contains($cfg.privateDnsZoneId)) {
                    $wiredZoneIds.Add($cfg.privateDnsZoneId) | Out-Null
                }
            }
        }
    }

    # ---- narrow the required zones to the sub-resources actually linked ----
    $groupIds = $groupIds | Where-Object { $_ } | Sort-Object -Unique
    $effectiveZones = @()
    foreach ($g in $groupIds) {
        $k = $g.ToLower()
        if ($groupIdZone.ContainsKey($k)) { $effectiveZones += $groupIdZone[$k] }
    }
    $effectiveZones = $effectiveZones | Sort-Object -Unique
    if ($effectiveZones.Count -eq 0) {
        $effectiveZones = $Target.Zones
    } else {
        Add-Result $area 'Private endpoint sub-resources' 'INFO' "groupIds: $($groupIds -join ', ') -> zones required: $($effectiveZones -join ', ')"
    }

    # ---- assemble the full zone set: wired zones PLUS expected zones -------    # (a PE with no zone group still needs its records validated, so we never
    #  rely on the zone group alone to decide what to check)
    $zoneSet = @{}   # zoneId -> zoneName
    foreach ($zid in $wiredZoneIds) { $zoneSet[$zid] = ($zid -split '/')[-1] }

    foreach ($expected in $effectiveZones) {
        $zonesFound = Find-PrivateDnsZone -ZoneName $expected
        if (-not $zonesFound -or $zonesFound.Count -eq 0) {
            Add-Result $area "Zone: $($expected -replace '^privatelink\.','')" 'WARN' "No private DNS zone named $expected is visible to you. Required only if that endpoint surface is in use, or the zone may live in a subscription you cannot read."
        } else {
            Add-Result $area "Zone: $($expected -replace '^privatelink\.','')" 'PASS' "$($zonesFound.Count) zone(s) in rg: $(($zonesFound | ForEach-Object { $_.resourceGroup }) -join ', ')"
            foreach ($zf in $zonesFound) { $zoneSet[$zf.id] = $expected }
        }
    }

    # ---- validate A records + VNet links for every zone in the set --------
    foreach ($zid in ($zoneSet.Keys | Sort-Object)) {
        $zname  = $zoneSet[$zid]
        $suffix = $zname -replace '^privatelink\.', ''

        $recs = Invoke-Arm -Id "$zid/A" -ApiVersion '2020-06-01'
        if ($null -eq $recs) {
            Add-Result $area "A records: $($zname -replace '^privatelink\.','')" 'WARN' 'Zone record sets not readable from this context (cross-subscription or missing Private DNS Zone Reader).'
            Test-ZoneVNetLinks -ZoneId $zid -ZoneName $zname -Area $area
            continue
        }
        $recList = ConvertTo-Array $recs.value

        # candidate label(s) to look for in this zone
        $checks = @()
        foreach ($kv in $fqdnIpMap.GetEnumerator()) {
            if ($kv.Key -like "*.$suffix") {
                $checks += [pscustomobject]@{ Label = ($kv.Key -split '\.')[0]; Want = @($kv.Value) }
            }
        }
        if ($checks.Count -eq 0 -and $allExpectedIps.Count -gt 0) {
            # no published FQDN map - fall back to the resource's DNS label
            $checks += [pscustomobject]@{ Label = $Target.Label; Want = @($allExpectedIps) }
        }

        if ($checks.Count -eq 0) {
            Add-Result $area "A records: $($zname -replace '^privatelink\.','')" 'INFO' "$($recList.Count) A record(s); no private endpoint IP available to compare against."
        }

        foreach ($chk in $checks) {
            $rec = $recList | Where-Object { $_.name -ieq $chk.Label } | Select-Object -First 1
            if (-not $rec) {
                $present = ($recList | ForEach-Object { $_.name }) -join ', '
                Add-Result $area "A record: $($chk.Label).$($zname -replace '^privatelink\.','')" 'FAIL' "No A record named '$($chk.Label)' in $zname. Clients resolving through this zone fall through to the public CNAME. Records present: $(if ($present) { $present } else { '(none)' })."
                continue
            }
            $recIps = (ConvertTo-Array $rec.properties.aRecords) | ForEach-Object { $_.ipv4Address }
            $hit = $recIps | Where-Object { $chk.Want -contains $_ }
            if ($hit) {
                Add-Result $area "A record: $($chk.Label).$($zname -replace '^privatelink\.','')" 'PASS' "$($chk.Label) -> $($recIps -join ',') (matches private endpoint NIC)."
            } else {
                Add-Result $area "A record: $($chk.Label).$($zname -replace '^privatelink\.','')" 'FAIL' "$($chk.Label) -> $($recIps -join ',') but the private endpoint NIC is $($chk.Want -join ','). Stale/incorrect record - traffic is sent to the wrong address."
            }
        }

        Test-ZoneVNetLinks -ZoneId $zid -ZoneName $zname -Area $area
    }
}

foreach ($t in $targets) {
    Write-Host ''
    Write-Host "    --- $(if ($t.Area) { $t.Area } else { $t.Name }) ---" -ForegroundColor Cyan
    Test-ResourcePrivateLink -Target $t
}

#endregion

#region ------------------------------------------- 5. injected subnet health

Write-Phase '5. Injected subnet health'

if ($topology -ne 'delegated-subnet') {
    Add-Result 'Subnet' 'Subnet checks' 'SKIP' "Topology is '$topology' - no customer delegated subnet to inspect."
} else {
    $subnet = Invoke-Arm -Id $injectedSubnetId -ApiVersion $script:ApiNet
    if (-not $subnet) {
        Add-Result 'Subnet' 'Read subnet' 'FAIL' "Cannot read $injectedSubnetId - it may have been deleted or lives in another subscription."
    } else {
        $sp = $subnet.properties

        $delegations = ConvertTo-Array $sp.delegations
        $delNames = $delegations | ForEach-Object { $_.properties.serviceName }
        if ($delNames -contains 'Microsoft.App/environments') {
            Add-Result 'Subnet' 'Delegation' 'PASS' 'Microsoft.App/environments'
        } elseif ($delNames.Count -eq 0) {
            Add-Result 'Subnet' 'Delegation' 'FAIL' 'Subnet has no delegation. Foundry agent injection requires delegation to Microsoft.App/environments.'
        } else {
            Add-Result 'Subnet' 'Delegation' 'FAIL' "Delegated to '$($delNames -join ',')' instead of Microsoft.App/environments."
        }

        $prefixes = @()
        if ($sp.addressPrefix) { $prefixes += $sp.addressPrefix }
        $prefixes += (ConvertTo-Array $sp.addressPrefixes)
        $sizes = $prefixes | ForEach-Object { Get-PrefixSize $_ } | Where-Object { $_ }
        $smallest = ($sizes | Measure-Object -Maximum).Maximum
        if ($null -eq $smallest) {
            Add-Result 'Subnet' 'Address space' 'WARN' 'Could not determine prefix size.'
        } elseif ($smallest -le 27) {
            Add-Result 'Subnet' 'Address space' 'PASS' "$($prefixes -join ',') (/$smallest meets the /27 minimum)."
        } else {
            Add-Result 'Subnet' 'Address space' 'FAIL' "$($prefixes -join ',') is /$smallest. Injection requires /27 or larger; the deployment will fail or be unable to scale."
        }

        if ($sp.networkSecurityGroup) {
            $nsgId = $sp.networkSecurityGroup.id
            $nsg = Invoke-Arm -Id $nsgId -ApiVersion $script:ApiNet
            $rules = ConvertTo-Array $nsg.properties.securityRules
            $denyOut = $rules | Where-Object { $_.properties.access -eq 'Deny' -and $_.properties.direction -eq 'Outbound' }
            $denyIn  = $rules | Where-Object { $_.properties.access -eq 'Deny' -and $_.properties.direction -eq 'Inbound' }
            Add-Result 'Subnet' 'NSG attached' 'INFO' "$(($nsgId -split '/')[-1]) - $($rules.Count) custom rule(s)"
            if ($denyOut) {
                Add-Result 'Subnet' 'NSG outbound denies' 'WARN' "Deny rules present: $(($denyOut | ForEach-Object { "$($_.name)[p$($_.properties.priority)] $($_.properties.destinationAddressPrefix):$($_.properties.destinationPortRange)" }) -join '; '). Confirm 443 to AzureCloud, Storage, and your dependency PE IPs is still permitted."
            }
            if ($denyIn) {
                Add-Result 'Subnet' 'NSG inbound denies' 'INFO' (($denyIn | ForEach-Object { "$($_.name)[p$($_.properties.priority)]" }) -join '; ')
            }
        } else {
            Add-Result 'Subnet' 'NSG attached' 'INFO' 'No NSG on the injected subnet.'
        }

        if ($sp.routeTable) {
            $rtId = $sp.routeTable.id
            $rt = Invoke-Arm -Id $rtId -ApiVersion $script:ApiNet
            $routes = ConvertTo-Array $rt.properties.routes
            $default = $routes | Where-Object { $_.properties.addressPrefix -eq '0.0.0.0/0' }
            if ($default) {
                $nh = ($default | ForEach-Object { "$($_.properties.nextHopType) $($_.properties.nextHopIpAddress)" }) -join '; '
                Add-Result 'Subnet' 'UDR default route' 'WARN' "0.0.0.0/0 -> $nh. Forced tunneling: if the appliance cannot reach Azure control-plane endpoints or drops return traffic, Foundry will time out even with perfect DNS."
            } else {
                Add-Result 'Subnet' 'UDR' 'INFO' "$(($rtId -split '/')[-1]) - $($routes.Count) route(s), no default route override."
            }
        } else {
            Add-Result 'Subnet' 'UDR' 'PASS' 'No route table - system routing.'
        }

        $svcEps = ConvertTo-Array $sp.serviceEndpoints
        if ($svcEps.Count -gt 0) {
            Add-Result 'Subnet' 'Service endpoints' 'WARN' "$(($svcEps | ForEach-Object { $_.service }) -join ', ') enabled. Service endpoints take precedence over private endpoint routing for those services and will bypass your private path."
        }

        $ipCfgs = ConvertTo-Array $sp.ipConfigurations
        Add-Result 'Subnet' 'IP consumption' 'INFO' "$($ipCfgs.Count) IP configuration(s) in use."
    }

    # is the injected VNet peered to the hub, if a hub was supplied?
    if ($HubVNetId -and $injectedVNetId) {
        $peers = Invoke-Arm -Id "$injectedVNetId/virtualNetworkPeerings" -ApiVersion $script:ApiNet
        $peerList = ConvertTo-Array $peers.value
        $hit = $peerList | Where-Object { $_.properties.remoteVirtualNetwork.id -ieq $HubVNetId }
        if ($hit) {
            $st = $hit.properties.peeringState
            if ($st -eq 'Connected') {
                Add-Result 'Subnet' 'Peering to hub' 'PASS' "$($hit.name) is Connected."
            } else {
                Add-Result 'Subnet' 'Peering to hub' 'FAIL' "$($hit.name) state=$st. Hub-linked DNS zones will not resolve from the injected VNet."
            }
        } else {
            Add-Result 'Subnet' 'Peering to hub' 'FAIL' 'Injected VNet is not peered to the supplied hub VNet. Hub-linked private DNS zones cannot be used from here.'
        }
    }

    # DNS servers configured on the injected VNet
    if ($injectedVNetId) {
        $vnet = Invoke-Arm -Id $injectedVNetId -ApiVersion $script:ApiNet
        $dns = ConvertTo-Array $vnet.properties.dhcpOptions.dnsServers
        if ($dns.Count -eq 0) {
            Add-Result 'Subnet' 'VNet DNS servers' 'INFO' 'Azure-provided DNS (168.63.129.16). Private DNS zones must be linked directly to this VNet.'
        } else {
            Add-Result 'Subnet' 'VNet DNS servers' 'INFO' "Custom DNS: $($dns -join ', '). Zone links on this VNet are irrelevant unless these servers forward to 168.63.129.16 or a Private Resolver inbound endpoint."
        }
    }
}

#endregion

#region ------------------------------------------- 6. client-side data plane

Write-Phase '6. Client-side resolution and reachability (this machine)'

if ($SkipClientTests) {
    Add-Result 'Client' 'DNS/TCP tests' 'SKIP' '-SkipClientTests was specified.'
} else {
    # which resolver is this machine using
    $resolverAddrs = @()
    try {
        $svrs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ServerAddresses.Count -gt 0 }
        $servers = $svrs | ForEach-Object { "$($_.InterfaceAlias)=$($_.ServerAddresses -join ',')" }
        $resolverAddrs = $svrs | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique
        Add-Result 'Client' 'Configured resolvers' 'INFO' ($servers -join ' | ')
    } catch {
        Add-Result 'Client' 'Configured resolvers' 'WARN' 'Could not enumerate DNS client settings.'
    }

    $publicResolvers = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '208.67.222.222')
    $usingPublicDns  = [bool]($resolverAddrs | Where-Object { $publicResolvers -contains $_ })

    # Build the FQDN test list, tagged by whether the endpoint is private-linkable.
    # Regional shared endpoints (speech, translator, regional api.cognitive.*) are
    # multi-tenant and have no per-account private endpoint - they must never be
    # reported as private-connectivity failures.
    $subLabel  = if ($props.customSubDomainName) { $props.customSubDomainName } else { $AccountName }
    $testItems = New-Object System.Collections.Generic.List[object]

    foreach ($f in $fqdns) {
        $isAccount = $f -like "$subLabel.*"
        $testItems.Add([pscustomobject]@{ Fqdn = $f; Private = $isAccount; Source = $AccountName }) | Out-Null
    }
    foreach ($t in ($targets | Select-Object -Skip 1)) {
        $res = Invoke-Arm -Id $t.Id -ApiVersion ($typeApi[$t.Type] ?? $script:ApiCS)
        foreach ($pec in (ConvertTo-Array $res.properties.privateEndpointConnections)) {
            $peId = $pec.properties.privateEndpoint.id
            if (-not $peId) { continue }
            $pe = Invoke-Arm -Id $peId -ApiVersion $script:ApiNet
            foreach ($cfg in (ConvertTo-Array $pe.properties.customDnsConfigs)) {
                if ($cfg.fqdn -and -not ($testItems.Fqdn -contains $cfg.fqdn)) {
                    $testItems.Add([pscustomobject]@{ Fqdn = $cfg.fqdn; Private = $true; Source = $t.Name }) | Out-Null
                }
            }
        }
    }

    $privateItems = @($testItems | Where-Object { $_.Private })
    $sharedItems  = @($testItems | Where-Object { -not $_.Private })

    if ($sharedItems.Count -gt 0) {
        Add-Result 'Client' 'Regional shared endpoints' 'INFO' "Not private-linkable, excluded from pass/fail: $(($sharedItems.Fqdn) -join ', '). These are multi-tenant regional endpoints; they resolve publicly by design. If your workload calls them from a locked-down VNet, they need firewall/UDR allowances rather than a private endpoint."
    }
    if ($privateItems.Count -eq 0) {
        Add-Result 'Client' 'DNS/TCP tests' 'WARN' 'No private-linkable FQDNs resolved from the control plane to test.'
    }

    $privateResolveCount = 0
    $publicBlockedCount  = 0
    $indirectFqdns       = New-Object System.Collections.Generic.List[string]

    # Probe every endpoint concurrently, then report serially so live output
    # stays ordered and severity logic keeps access to script state.
    $probes = @(Test-EndpointReachability -Items $privateItems -Throttle 8)
    $probeMap = @{}
    foreach ($pr in $probes) { $probeMap[$pr.Fqdn] = $pr }

    foreach ($item in $privateItems) {
        $fqdn  = $item.Fqdn
        $probe = $probeMap[$fqdn]
        if (-not $probe) { continue }

        if ($probe.ResolveError) {
            Add-Result 'Client' "Resolve $fqdn" 'FAIL' "NXDOMAIN / no answer: $($probe.ResolveError). This machine cannot resolve the endpoint at all."
            continue
        }

        $addrs = @($probe.Addrs)
        if ($addrs.Count -eq 0) {
            Add-Result 'Client' "Resolve $fqdn" 'FAIL' 'CNAME resolved but no A record returned. The privatelink zone is not answering for this client.'
            continue
        }

        $priv = $addrs | Where-Object { Test-PrivateIPv4 $_ }
        $pub  = $addrs | Where-Object { -not (Test-PrivateIPv4 $_) }

        if ($priv -and -not $pub) {
            $privateResolveCount++
            $known = $priv | Where-Object { $script:KnownPeIps -contains $_ }
            if ($known) {
                Add-Result 'Client' "Resolve $fqdn" 'PASS' "PRIVATE (direct) -> $($known -join ', ') - matches a discovered private endpoint NIC."
            } elseif ($script:KnownPeIps.Count -gt 0) {
                # Private address space, but not one of this deployment's endpoint
                # NICs. Typical of a NetScaler/F5/proxy VIP, a DNS forwarder that
                # rewrites answers, or a stale record. Not provably wrong - traffic
                # may well be forwarded correctly - so this is a WARN plus a
                # certificate check below, not a failure.
                $indirectFqdns.Add($fqdn) | Out-Null
                Add-Result 'Client' "Resolve $fqdn" 'WARN' "PRIVATE (indirect) -> $($priv -join ', '). This is private address space but NOT one of this deployment's private endpoint NICs ($($script:KnownPeIps -join ', ')). Something in the path is answering on the service's behalf - an ADC/proxy VIP (NetScaler, F5), a DNS forwarder that rewrites answers, or a stale record. Check the TLS identity below to see whether it still reaches the right backend."
            } else {
                Add-Result 'Client' "Resolve $fqdn" 'PASS' "PRIVATE -> $($priv -join ', ')"
            }
        } elseif ($priv -and $pub) {
            $privateResolveCount++
            Add-Result 'Client' "Resolve $fqdn" 'WARN' "SPLIT-BRAIN -> private $($priv -join ',') AND public $($pub -join ','). Some clients will take the public path."
        } else {
            # Severity is driven by the service's own config, not by this machine's
            # vantage point: if the service refuses public traffic, resolving to the
            # public frontend means the client provably cannot reach it.
            $blocked = $script:PublicDisabled[$item.Source] -eq $true
            $why = if ($usingPublicDns) {
                "This machine is using a public DNS resolver ($($resolverAddrs -join ', ')) and is off the private network."
            } else {
                "Resolver(s) $($resolverAddrs -join ', ') are not answering from the private DNS zone."
            }
            if ($blocked) {
                Add-Result 'Client' "Resolve $fqdn" 'FAIL' "PUBLIC ENDPOINT -> $($pub -join ', '). NOT reaching the private endpoint. $($item.Source) has publicNetworkAccess Disabled, so this address WILL refuse the connection - from this machine the service is unreachable. $why"
                $publicBlockedCount++
            } else {
                Add-Result 'Client' "Resolve $fqdn" 'WARN' "PUBLIC ENDPOINT -> $($pub -join ', '). NOT reaching the private endpoint; traffic from here egresses over the internet to the public frontend. $($item.Source) still allows public access, so calls may succeed while bypassing your private path entirely. $why"
            }
            # Still report who answered on the public path - it distinguishes
            # "reached Azure's public frontend" from "a proxy intercepted this".
            if ($probe.HttpIdValue) {
                Add-Result 'Client' "Service identity $fqdn" 'INFO' "Public path answered HTTP $($probe.HttpStatus) with $($probe.HttpIdHeader)=$($probe.HttpIdValue), i.e. the genuine Azure frontend - not an intercepting proxy. This says nothing about the private path."
            } elseif ($probe.HttpStatus) {
                Add-Result 'Client' "Service identity $fqdn" 'WARN' "Public path answered HTTP $($probe.HttpStatus) with no Azure per-request id header - something other than the real service replied (proxy, captive portal, or error page)."
            }
            continue
        }

        # --- TCP reachability (only meaningful once we have a private answer) ---
        if ($probe.Tcp) {
            Add-Result 'Client' "TCP 443 $fqdn" 'PASS' "$($probe.TcpTarget):443 open."
        } else {
            Add-Result 'Client' "TCP 443 $fqdn" 'FAIL' "$($probe.TcpTarget):443 unreachable. Check the NSG on the private endpoint subnet, UDR/firewall on the path, and that this machine is on-network (VPN/ExpressRoute)."
        }

        # --- TLS identity (through a proxy this is the real proof of backend) ---
        if ($probe.Tcp) {
            if ($probe.TlsIssuer) {
                $nameOk = Test-CertNameMatch -Fqdn $fqdn -SanText $probe.TlsSan -Subject $probe.TlsSubject
                $trusted = $probe.TlsIssuer -match 'Microsoft|DigiCert|Baltimore|Entrust'

                if ($nameOk -eq $false) {
                    Add-Result 'Client' "TLS identity $fqdn" 'FAIL' "The certificate presented does not cover $fqdn. Issuer: $($probe.TlsIssuer). Whatever answered on this address is NOT the intended service - a proxy or VIP is terminating the connection and forwarding to the wrong backend (or not forwarding at all)."
                } elseif ($nameOk -eq $true -and $trusted) {
                    Add-Result 'Client' "TLS identity $fqdn" 'PASS' "Certificate covers $fqdn and is issued by $($probe.TlsIssuer). Traffic is reaching the genuine service even if the address is a proxy VIP."
                } elseif ($nameOk -eq $true) {
                    Add-Result 'Client' "TLS identity $fqdn" 'WARN' "Certificate covers $fqdn but the issuer '$($probe.TlsIssuer)' is not a known Microsoft/public CA - a TLS-intercepting proxy is re-signing the connection. SDKs that pin or validate strictly will fail."
                } elseif (-not $trusted) {
                    Add-Result 'Client' "TLS identity $fqdn" 'WARN' "Issuer '$($probe.TlsIssuer)' is not a known Microsoft/public CA. A TLS-intercepting proxy is in the path and will break SDK calls that pin or validate strictly."
                } else {
                    Add-Result 'Client' "TLS identity $fqdn" 'INFO' "Issuer: $($probe.TlsIssuer)"
                }
                if ($Detailed -and $probe.TlsSan) { Add-Result 'Client' "TLS SAN $fqdn" 'INFO' $probe.TlsSan }
            } elseif ($probe.TlsError) {
                Add-Result 'Client' "TLS identity $fqdn" 'WARN' "TLS handshake failed: $($probe.TlsError)"
            }

            # --- service identity: did the REAL service answer? -------------
            # Scope note: this proves WHO answered, not whether network policy
            # allowed it. No credentials are sent, so a 401/403 cannot be
            # attributed to the network ACL rather than to missing auth.
            if ($probe.HttpStatus -or $probe.HttpError) {
                $svcName = $item.Source
                if ($probe.HttpIdValue) {
                    Add-Result 'Client' "Service identity $fqdn" 'PASS' "HTTP $($probe.HttpStatus) carrying $($probe.HttpIdHeader)=$($probe.HttpIdValue). Only the genuine Azure service stamps that header, so the request reached $svcName itself rather than being absorbed or answered by an intermediary. (401/403 is expected - the probe is unauthenticated.)"
                } elseif ($probe.HttpStatus) {
                    Add-Result 'Client' "Service identity $fqdn" 'WARN' "HTTP $($probe.HttpStatus) but the response carries none of the Azure per-request id headers (apim-request-id / x-ms-request-id / x-ms-activity-id / request-id). Something answered on the service's behalf - a proxy, captive portal, or error page - rather than the request reaching $svcName. Body: $($probe.HttpBody)"
                } else {
                    Add-Result 'Client' "Service identity $fqdn" 'WARN' "TLS succeeded but the HTTP probe failed: $($probe.HttpError). The listener is not behaving like $svcName."
                }
            }
        }
    }

    # A single address answering for many distinct services is the signature of a
    # shared VIP (ADC/proxy) rather than per-service private endpoints.
    $ipToFqdns = @{}
    foreach ($item in $privateItems) {
        $pr = $probeMap[$item.Fqdn]
        if (-not $pr) { continue }
        foreach ($a in @($pr.Addrs)) {
            if (-not $ipToFqdns.ContainsKey($a)) { $ipToFqdns[$a] = New-Object System.Collections.Generic.List[string] }
            $ipToFqdns[$a].Add($item.Fqdn) | Out-Null
        }
    }
    foreach ($kv in $ipToFqdns.GetEnumerator()) {
        if ($kv.Value.Count -gt 1 -and (Test-PrivateIPv4 $kv.Key) -and ($script:KnownPeIps -notcontains $kv.Key)) {
            Add-Result 'Client' 'Shared VIP detected' 'WARN' "$($kv.Value.Count) different service FQDNs all resolve to $($kv.Key): $($kv.Value -join ', '). Distinct private endpoints have distinct NIC addresses, so this is one appliance (NetScaler/F5/proxy) fronting them all. Client-side checks can only confirm the certificate identity per FQDN; which backend that appliance actually selects must be verified on the appliance itself."
        }
    }

    # Single, clear verdict on where this client sits relative to the private network.
    if ($privateItems.Count -gt 0) {
        if ($privateResolveCount -eq 0 -and $publicBlockedCount -gt 0) {
            Add-Result 'Client' 'Vantage point' 'FAIL' "NOT ON THE PRIVATE NETWORK, AND THE SERVICES REFUSE PUBLIC TRAFFIC. All $($privateItems.Count) endpoint(s) resolved to the PUBLIC frontend, and $publicBlockedCount of them belong to resources with publicNetworkAccess Disabled - so from this machine those services are unreachable, full stop. Resolver(s) in use: $($resolverAddrs -join ', '). This is expected if you are running from a laptop rather than the private network; the control-plane and DNS-zone findings above remain authoritative. To test the private path, re-run from a VM in the injected VNet or a host on VPN/ExpressRoute using the corporate resolver."
        } elseif ($privateResolveCount -eq 0 -and $usingPublicDns) {
            Add-Result 'Client' 'Vantage point' 'WARN' "NOT ON THE PRIVATE NETWORK. All $($privateItems.Count) endpoint(s) resolved to the PUBLIC frontend, not the private endpoint, because this machine uses a public DNS resolver ($($resolverAddrs -join ', ')). The client-side results above therefore prove nothing about the private path - the control-plane and DNS-zone findings are the authoritative ones. Re-run from a VM in the injected VNet, or a host on VPN/ExpressRoute using the corporate resolver."
        } elseif ($privateResolveCount -eq 0) {
            Add-Result 'Client' 'Vantage point' 'FAIL' "This machine uses resolver(s) $($resolverAddrs -join ', ') yet resolved 0 of $($privateItems.Count) private endpoints privately. If this host is meant to be on-network, the resolver is not forwarding to Azure DNS (168.63.129.16) or the Private Resolver inbound endpoint, or the zone is not linked to the VNet this host sits in."
        } elseif ($privateResolveCount -lt $privateItems.Count) {
            Add-Result 'Client' 'Vantage point' 'WARN' "$privateResolveCount of $($privateItems.Count) private endpoints resolved privately from this machine. Partial resolution usually means one zone is missing a VNet link or an A record."
        } else {
            Add-Result 'Client' 'Vantage point' 'PASS' "All $($privateItems.Count) private endpoints resolved to private addresses from this machine."
        }
    }
}

#endregion

#region ------------------------------------------------------- 7. verdict table

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor White
Write-Host '   VERDICT (consolidated)' -ForegroundColor White
Write-Host '  ============================================================' -ForegroundColor White
Write-Host ''

$maxDetail = if ($Detailed) { 4000 } else { 150 }

# Group in the order findings were produced, not alphabetically - the report
# should read top-down the way the sweep ran (Prereq, Context, Account, ...,
# then each service), instead of putting "AI Search" above "Foundry".
$areaOrder = New-Object System.Collections.Generic.List[string]
foreach ($r in $script:Results) {
    if (-not $areaOrder.Contains($r.Area)) { $areaOrder.Add($r.Area) | Out-Null }
}

foreach ($areaName in $areaOrder) {
    Write-Host ("  {0}" -f $areaName) -ForegroundColor White
    foreach ($r in ($script:Results | Where-Object { $_.Area -eq $areaName })) {
        Write-ResultLine -Row $r -MaxDetail $maxDetail
    }
    Write-Host ''
}

# Deployment scope decides the verdict and the exit code. Client-side results
# describe the machine this ran from - a laptop off the private network cannot
# make a correctly configured deployment "failed".
$depResults = @($script:Results | Where-Object { $_.Scope -eq 'Deployment' })
$cliResults = @($script:Results | Where-Object { $_.Scope -eq 'Client' })

$fails = @($depResults | Where-Object { $_.Status -eq 'FAIL' })
$warns = @($depResults | Where-Object { $_.Status -eq 'WARN' })
$notes = @($depResults | Where-Object { $_.Status -eq 'PASS-NOTE' })
$passes = @($depResults | Where-Object { $_.Status -eq 'PASS' })

$cliFails = @($cliResults | Where-Object { $_.Status -eq 'FAIL' })
$cliWarns = @($cliResults | Where-Object { $_.Status -eq 'WARN' })

$deployVerdict = if ($fails.Count -gt 0) { 'FAIL' } elseif ($warns.Count -gt 0) { 'WARN' } else { 'PASS' }
$verdictColor  = @{ 'PASS' = 'Green'; 'WARN' = 'Yellow'; 'FAIL' = 'Red' }[$deployVerdict]

Write-Host '  ------------------------------------------------------------' -ForegroundColor White
Write-Host '   DEPLOYMENT CONFIGURATION' -ForegroundColor White -NoNewline
Write-Host "   $deployVerdict" -ForegroundColor $verdictColor
Write-Host ("   {0} FAIL   {1} WARN   {2} PASS-NOTE   {3} PASS" -f `
    $fails.Count, $warns.Count, $notes.Count, $passes.Count) -ForegroundColor DarkGray

if ($cliResults.Count -gt 0) {
    $cliSummary = if ($cliFails.Count -gt 0 -or $cliWarns.Count -gt 0) {
        "$($cliFails.Count) FAIL   $($cliWarns.Count) WARN   (reflects THIS machine's network position, not the deployment)"
    } else {
        'no issues from this machine'
    }
    $cliColor = if ($cliFails.Count -gt 0) { 'Red' } elseif ($cliWarns.Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host '   CLIENT CONNECTIVITY (this host)' -ForegroundColor White
    Write-Host "   $cliSummary" -ForegroundColor $cliColor
}
Write-Host '  ------------------------------------------------------------' -ForegroundColor White

if ($fails.Count -gt 0) {
    Write-Host ''
    Write-Host '   Fix these first (deployment):' -ForegroundColor Red
    foreach ($f in $fails) {
        Write-Host "    * [$($f.Area)] $($f.Check)" -ForegroundColor Red
        Write-Host "        $($f.Detail)" -ForegroundColor DarkGray
    }
}

if ($cliFails.Count -gt 0) {
    Write-Host ''
    if ($deployVerdict -eq 'PASS') {
        Write-Host '   The deployment configuration is healthy. The failures below are about THIS' -ForegroundColor Yellow
        Write-Host '   machine reaching it, not about the deployment being wrong:' -ForegroundColor Yellow
    } else {
        Write-Host '   Client-side (depends on where this ran from):' -ForegroundColor Yellow
    }
    foreach ($f in $cliFails) {
        Write-Host "    * $($f.Check)" -ForegroundColor Yellow
    }
    Write-Host '    Re-run from a host inside the private network to validate the data path.' -ForegroundColor DarkGray
}
Write-Host ''

#endregion

#region ------------------------------------------------------- 8. HTML export

function Export-HtmlReport {
    param([Parameter(Mandatory)][string] $Path)

    $enc = {
        param($s)
        if ($null -eq $s) { return '' }
        [System.Net.WebUtility]::HtmlEncode([string]$s)
    }

    $passCount = $passes.Count
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $overall   = $deployVerdict

    # Build the client banner separately - nesting $() inside a here-string
    # subexpression is fragile and hard to read.
    $clientBanner = ''
    if ($cliFails.Count -gt 0 -or $cliWarns.Count -gt 0) {
        $clientBanner = "<div class=""banner b-WARN"">Client connectivity from $(& $enc $env:COMPUTERNAME): $($cliFails.Count) fail, $($cliWarns.Count) warn &mdash; this reflects where the script ran, not whether the deployment is correct.</div>"
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Foundry private connectivity - $(& $enc $AccountName)</title>
<style>
 :root{--bg:#0f1117;--card:#171a21;--line:#272b34;--txt:#e6e6e6;--mut:#9aa0aa;
       --pass:#3fb950;--note:#2ea043;--warn:#d29922;--fail:#f85149;--info:#8b949e;--skip:#6e7681;}
 @media(prefers-color-scheme:light){
  :root{--bg:#f6f8fa;--card:#fff;--line:#d8dee4;--txt:#1f2328;--mut:#59636e;--info:#59636e;--skip:#8c959f;}}
 *{box-sizing:border-box}
 body{margin:0;padding:32px;background:var(--bg);color:var(--txt);
      font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
 h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:28px 0 10px;color:var(--txt)}
 .sub{color:var(--mut);font-size:13px;margin-bottom:20px}
 .cards{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0 26px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 18px;min-width:96px}
 .card .n{font-size:22px;font-weight:600} .card .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
 .banner{border-radius:8px;padding:12px 16px;margin-bottom:22px;font-weight:600;border:1px solid}
 .b-PASS{background:rgba(63,185,80,.12);border-color:var(--pass);color:var(--pass)}
 .b-WARN{background:rgba(210,153,34,.12);border-color:var(--warn);color:var(--warn)}
 .b-FAIL{background:rgba(248,81,73,.12);border-color:var(--fail);color:var(--fail)}
 table{width:100%;border-collapse:collapse;background:var(--card);
       border:1px solid var(--line);border-radius:8px;overflow:hidden}
 th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
    color:var(--mut);padding:9px 12px;border-bottom:1px solid var(--line);font-weight:600}
 td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
 tr:last-child td{border-bottom:none}
 .s{font-weight:700;font-size:11px;letter-spacing:.04em;white-space:nowrap}
 .s-PASS{color:var(--pass)} .s-PASSNOTE{color:var(--note)} .s-WARN{color:var(--warn)}
 .s-FAIL{color:var(--fail)} .s-INFO{color:var(--info)} .s-SKIP{color:var(--skip)}
 td.chk{white-space:nowrap;font-weight:500} td.det{color:var(--mut)}
 .fixlist{background:var(--card);border:1px solid var(--fail);border-radius:8px;padding:14px 18px;margin-bottom:26px}
 .fixlist li{margin-bottom:10px} .fixlist .d{color:var(--mut);font-size:13px}
 footer{color:var(--mut);font-size:12px;margin-top:32px;border-top:1px solid var(--line);padding-top:14px}
 code{background:rgba(127,127,127,.14);padding:1px 5px;border-radius:4px;font-size:12px}
</style></head><body>
<h1>Microsoft Foundry &mdash; private connectivity diagnostics</h1>
<div class="sub">
  <strong>$(& $enc $AccountName)</strong> in <code>$(& $enc $ResourceGroup)</code>
  &middot; subscription <code>$(& $enc $SubscriptionId)</code>
  &middot; generated $generated
</div>
<div class="banner b-$overall">Deployment configuration: $overall</div>
$clientBanner
<div class="cards">
  <div class="card"><div class="n s-FAIL">$($fails.Count)</div><div class="l">Fail</div></div>
  <div class="card"><div class="n s-WARN">$($warns.Count)</div><div class="l">Warn</div></div>
  <div class="card"><div class="n s-PASSNOTE">$($notes.Count)</div><div class="l">Pass-note</div></div>
  <div class="card"><div class="n s-PASS">$passCount</div><div class="l">Pass</div></div>
</div>
<div class="sub">Counts above cover the deployment configuration. Client-side checks are listed separately below.</div>
"@)

    if ($fails.Count -gt 0) {
        [void]$sb.Append('<h2>Fix these first (deployment)</h2><div class="fixlist"><ol>')
        foreach ($f in $fails) {
            [void]$sb.Append("<li><strong>[$(& $enc $f.Area)] $(& $enc $f.Check)</strong><div class='d'>$(& $enc $f.Detail)</div></li>")
        }
        [void]$sb.Append('</ol></div>')
    }

    if ($cliFails.Count -gt 0) {
        $lead = if ($deployVerdict -eq 'PASS') {
            'The deployment configuration is healthy. These relate to this machine reaching it, not to the deployment being wrong. Re-run from a host inside the private network to validate the data path.'
        } else {
            'Client-side observations. These depend on where the script ran from.'
        }
        [void]$sb.Append("<h2>Client connectivity from this host</h2><div class='fixlist' style='border-color:var(--warn)'><p class='d'>$(& $enc $lead)</p><ol>")
        foreach ($f in $cliFails) {
            [void]$sb.Append("<li><strong>$(& $enc $f.Check)</strong><div class='d'>$(& $enc $f.Detail)</div></li>")
        }
        [void]$sb.Append('</ol></div>')
    }

    # Preserve discovery order rather than sorting alphabetically.
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($r in $script:Results) { if (-not $order.Contains($r.Area)) { $order.Add($r.Area) | Out-Null } }

    foreach ($areaName in $order) {
        [void]$sb.Append("<h2>$(& $enc $areaName)</h2>")
        [void]$sb.Append('<table><thead><tr><th style="width:88px">Status</th><th style="width:280px">Check</th><th>Detail</th></tr></thead><tbody>')
        foreach ($r in ($script:Results | Where-Object { $_.Area -eq $areaName })) {
            $cls = 's-' + ($r.Status -replace '-', '')
            [void]$sb.Append("<tr><td class='s $cls'>$(& $enc $r.Status)</td><td class='chk'>$(& $enc $r.Check)</td><td class='det'>$(& $enc $r.Detail)</td></tr>")
        }
        [void]$sb.Append('</tbody></table>')
    }

    [void]$sb.Append(@"
<footer>
  Read-only diagnostic. Control-plane and DNS findings are authoritative from anywhere;
  client-side results reflect the host this ran on
  ($(& $enc $env:COMPUTERNAME)$(if ($SkipClientTests) { ', client tests skipped' })).
</footer></body></html>
"@)

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}

# Non-interactive export when asked for explicitly; otherwise offer it, unless
# the host cannot prompt (CI, scheduled task, redirected stdin) - the script must
# never block waiting on input that will not arrive.
$defaultHtml = Join-Path (Get-Location) "FoundryConnectivity-$AccountName-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

if ($ExportHtml -or $HtmlPath) {
    $target = if ($HtmlPath) { $HtmlPath } else { $defaultHtml }
    if ($target -notmatch '\.html?$') { $target += '.html' }
    try {
        Export-HtmlReport -Path $target
        Write-Host "  Report written: $((Resolve-Path $target).Path)" -ForegroundColor Green
    } catch {
        Write-Host "  Could not write the report: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ''
} elseif (-not [System.Console]::IsInputRedirected) {
    $answer = $null
    try { $answer = Read-Host '  Export an HTML report? [y/N]' } catch { $answer = 'n' }
    if ($answer -match '^\s*(y|yes)\s*$') {
        $custom = Read-Host "  Path [$defaultHtml]"
        $target = if ([string]::IsNullOrWhiteSpace($custom)) { $defaultHtml } else { $custom.Trim() }
        if ($target -notmatch '\.html?$') { $target += '.html' }
        try {
            Export-HtmlReport -Path $target
            $full = (Resolve-Path $target).Path
            Write-Host "  Report written: $full" -ForegroundColor Green
            $open = Read-Host '  Open it now? [y/N]'
            if ($open -match '^\s*(y|yes)\s*$') { Start-Process $full }
        } catch {
            Write-Host "  Could not write the report: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ''
}

# Exit code reflects the DEPLOYMENT only. A correctly configured deployment
# should not report failure just because the operator ran the script from a
# laptop that is not on the private network.
if ($fails.Count -gt 0) { exit 1 } else { exit 0 }

#endregion

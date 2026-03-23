<#
.SYNOPSIS
    Generates an HTML report of Azure AD App Registrations and their Microsoft Graph permissions.

.DESCRIPTION
    Connects to Microsoft Graph, retrieves all app registrations in the tenant,
    resolves their delegated and application (role) Microsoft Graph permissions,
    and outputs a styled HTML report.

.PARAMETER OutputPath
    Path for the generated HTML file. Defaults to AppRegistrationReport.html in the current directory.

.PARAMETER TenantId
    Optional tenant ID. If omitted, the interactive login determines the tenant.

.PARAMETER AuthMethod
    Authentication method to use. Valid values:
      Interactive      - Browser-based interactive login (default)
      DeviceCode       - Device code flow for headless/remote sessions
      ClientSecret     - Service principal with client secret
      Certificate      - Service principal with certificate thumbprint
      ManagedIdentity  - Azure Managed Identity (system or user-assigned)

.PARAMETER ClientId
    Application (client) ID for ClientSecret, Certificate, or user-assigned ManagedIdentity auth.

.PARAMETER ClientSecret
    Client secret value for ClientSecret auth. Prefer ClientSecretCredential or environment
    variables over passing secrets on the command line.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for Certificate auth. The certificate must be in the current user's
    certificate store.

.EXAMPLE
    .\Get-AppRegistrationReport.ps1
    Interactive browser login.

.EXAMPLE
    .\Get-AppRegistrationReport.ps1 -AuthMethod DeviceCode -TenantId "contoso.onmicrosoft.com"
    Device code flow for headless sessions.

.EXAMPLE
    .\Get-AppRegistrationReport.ps1 -AuthMethod ClientSecret -TenantId "contoso.onmicrosoft.com" -ClientId "00000000-0000-0000-0000-000000000000" -ClientSecret (Read-Host -AsSecureString "Secret")
    Service principal with client secret.

.EXAMPLE
    .\Get-AppRegistrationReport.ps1 -AuthMethod Certificate -TenantId "contoso.onmicrosoft.com" -ClientId "00000000-0000-0000-0000-000000000000" -CertificateThumbprint "A1B2C3..."
    Service principal with certificate.

.EXAMPLE
    .\Get-AppRegistrationReport.ps1 -AuthMethod ManagedIdentity
    System-assigned managed identity on an Azure host.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "AppRegistrationReport.html"),
    [string]$TenantId,
    [ValidateSet("Interactive", "DeviceCode", "ClientSecret", "Certificate", "ManagedIdentity")]
    [string]$AuthMethod = "Interactive",
    [string]$ClientId,
    [SecureString]$ClientSecret,
    [string]$CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 1. Ensure the Microsoft.Graph module is available ──────────────────────
$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing module $mod ..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
}

# ── 2. Connect to Microsoft Graph ─────────────────────────────────────────
$connectParams = @{}
if ($TenantId) { $connectParams["TenantId"] = $TenantId }

switch ($AuthMethod) {
    "Interactive" {
        $connectParams["Scopes"] = @("Application.Read.All", "Directory.Read.All")
    }
    "DeviceCode" {
        $connectParams["Scopes"]        = @("Application.Read.All", "Directory.Read.All")
        $connectParams["UseDeviceCode"] = $true
        # WAM can interfere with DeviceCode token caching on Windows; disable it for this flow
        Set-MgGraphOption -DisableLoginByWAM $true
    }
    "ClientSecret" {
        if (-not $ClientId)     { throw "ClientId is required for ClientSecret authentication." }
        if (-not $ClientSecret) { throw "ClientSecret is required for ClientSecret authentication." }
        if (-not $TenantId)     { throw "TenantId is required for ClientSecret authentication." }
        $credential = [System.Management.Automation.PSCredential]::new($ClientId, $ClientSecret)
        $connectParams["ClientSecretCredential"] = $credential
    }
    "Certificate" {
        if (-not $ClientId)              { throw "ClientId is required for Certificate authentication." }
        if (-not $CertificateThumbprint) { throw "CertificateThumbprint is required for Certificate authentication." }
        if (-not $TenantId)              { throw "TenantId is required for Certificate authentication." }
        $connectParams["ClientId"]             = $ClientId
        $connectParams["CertificateThumbprint"] = $CertificateThumbprint
    }
    "ManagedIdentity" {
        $connectParams["Identity"] = $true
        if ($ClientId) { $connectParams["ClientId"] = $ClientId }
    }
}

Write-Host "Connecting to Microsoft Graph ($AuthMethod)..." -ForegroundColor Cyan
Connect-MgGraph @connectParams -NoWelcome
Write-Host "Connected." -ForegroundColor Green

# ── 3. Build a lookup table: Graph permission ID → friendly name + type ───
Write-Host "Loading Microsoft Graph service principal permission catalogue..." -ForegroundColor Cyan

# The well-known appId for Microsoft Graph
$graphAppId = "00000003-0000-0000-c000-000000000000"
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -Property Id, AppRoles, Oauth2PermissionScopes

$permissionLookup = @{}

# Application permissions (appRoles)
foreach ($role in $graphSp.AppRoles) {
    $permissionLookup[$role.Id] = @{
        Name = $role.Value
        Type = "Application"
        Description = $role.DisplayName
    }
}

# Delegated permissions (oauth2PermissionScopes)
foreach ($scope in $graphSp.Oauth2PermissionScopes) {
    $permissionLookup[$scope.Id] = @{
        Name  = $scope.Value
        Type  = "Delegated"
        Description = $scope.AdminConsentDisplayName
    }
}

Write-Host "Loaded $($permissionLookup.Count) Graph permission definitions." -ForegroundColor Green

# ── 4. Retrieve all app registrations ─────────────────────────────────────
Write-Host "Retrieving app registrations..." -ForegroundColor Cyan
$apps = Get-MgApplication -All -Property Id, AppId, DisplayName, RequiredResourceAccess, SignInAudience, CreatedDateTime

Write-Host "Found $($apps.Count) app registrations." -ForegroundColor Green

# ── 5. Build report data ──────────────────────────────────────────────────
$reportRows = [System.Collections.Generic.List[PSObject]]::new()

foreach ($app in $apps) {
    # Filter to Microsoft Graph resource access entries only
    $graphAccess = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $graphAppId }

    $delegated    = [System.Collections.Generic.List[string]]::new()
    $appRoles     = [System.Collections.Generic.List[string]]::new()

    foreach ($resource in $graphAccess) {
        foreach ($access in $resource.ResourceAccess) {
            $id = $access.Id
            if ($permissionLookup.ContainsKey($id)) {
                $entry = $permissionLookup[$id]
                if ($entry.Type -eq "Delegated") {
                    $delegated.Add($entry.Name)
                } else {
                    $appRoles.Add($entry.Name)
                }
            } else {
                # Fallback: show the raw ID when the catalogue doesn't contain it
                if ($access.Type -eq "Scope") {
                    $delegated.Add("Unknown ($id)")
                } else {
                    $appRoles.Add("Unknown ($id)")
                }
            }
        }
    }

    $reportRows.Add([PSCustomObject]@{
        DisplayName        = $app.DisplayName
        AppId              = $app.AppId
        SignInAudience     = $app.SignInAudience
        Created            = if ($app.CreatedDateTime) { $app.CreatedDateTime.ToString("yyyy-MM-dd") } else { "N/A" }
        DelegatedPerms     = ($delegated | Sort-Object) -join ", "
        ApplicationPerms   = ($appRoles  | Sort-Object) -join ", "
        DelegatedCount     = $delegated.Count
        ApplicationCount   = $appRoles.Count
    })
}

$reportRows = $reportRows | Sort-Object DisplayName

# ── 6. Generate HTML ──────────────────────────────────────────────────────
$totalApps       = $reportRows.Count
$appsWithAppPerms = ($reportRows | Where-Object { $_.ApplicationCount -gt 0 }).Count
$timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>App Registration &ndash; Graph Permissions Report</title>
<style>
    :root {
        --bg: #f4f6f9;
        --card-bg: #ffffff;
        --accent: #0078d4;
        --accent-light: #deecf9;
        --text: #333;
        --text-light: #666;
        --border: #e1e4e8;
        --danger: #d13438;
        --danger-light: #fde7e9;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: var(--bg); color: var(--text); padding: 24px;
    }
    h1 { font-size: 1.6rem; color: var(--accent); margin-bottom: 4px; }
    .subtitle { color: var(--text-light); font-size: 0.85rem; margin-bottom: 20px; }
    .summary {
        display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap;
    }
    .summary .card {
        background: var(--card-bg); border: 1px solid var(--border);
        border-radius: 8px; padding: 16px 24px; min-width: 180px;
    }
    .summary .card .number { font-size: 1.8rem; font-weight: 700; color: var(--accent); }
    .summary .card .label  { font-size: 0.8rem; color: var(--text-light); }
    .search-box {
        margin-bottom: 16px;
    }
    .search-box input {
        width: 100%; max-width: 420px; padding: 10px 14px;
        border: 1px solid var(--border); border-radius: 6px;
        font-size: 0.9rem; outline: none;
    }
    .search-box input:focus { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-light); }
    table {
        width: 100%; border-collapse: collapse; background: var(--card-bg);
        border: 1px solid var(--border); border-radius: 8px;
        overflow: hidden; font-size: 0.85rem;
    }
    thead th {
        background: var(--accent); color: #fff; padding: 12px 14px;
        text-align: left; position: sticky; top: 0; cursor: pointer;
        user-select: none; white-space: nowrap;
    }
    thead th:hover { background: #106ebe; }
    thead th .sort-arrow { margin-left: 4px; font-size: 0.7rem; }
    tbody tr { border-bottom: 1px solid var(--border); }
    tbody tr:hover { background: var(--accent-light); }
    tbody td { padding: 10px 14px; vertical-align: top; }
    .perm-tag {
        display: inline-block; padding: 2px 8px; margin: 2px;
        border-radius: 4px; font-size: 0.78rem; white-space: nowrap;
    }
    .perm-delegated { background: #e6f7ee; color: #1a7f37; }
    .perm-application { background: var(--danger-light); color: var(--danger); }
    .perm-none { color: #999; font-style: italic; }
    .badge {
        display: inline-block; padding: 1px 7px; border-radius: 10px;
        font-size: 0.75rem; font-weight: 600; margin-left: 6px;
    }
    .badge-app  { background: var(--danger-light); color: var(--danger); }
    .badge-del  { background: #e6f7ee; color: #1a7f37; }
    footer { margin-top: 24px; color: var(--text-light); font-size: 0.75rem; text-align: center; }
</style>
</head>
<body>

<h1>&#x1F4CB; App Registration &ndash; Graph Permissions Report</h1>
<p class="subtitle">Generated $timestamp</p>

<div class="summary">
    <div class="card"><div class="number">$totalApps</div><div class="label">Total App Registrations</div></div>
    <div class="card"><div class="number">$appsWithAppPerms</div><div class="label">Apps with Application Permissions</div></div>
</div>

<div class="search-box">
    <input type="text" id="search" placeholder="Filter by app name, permission, or App ID..." />
</div>

<table id="reportTable">
<thead>
<tr>
    <th onclick="sortTable(0)">App Name <span class="sort-arrow">&#x25B2;&#x25BC;</span></th>
    <th onclick="sortTable(1)">App (Client) ID <span class="sort-arrow">&#x25B2;&#x25BC;</span></th>
    <th onclick="sortTable(2)">Audience <span class="sort-arrow">&#x25B2;&#x25BC;</span></th>
    <th onclick="sortTable(3)">Created <span class="sort-arrow">&#x25B2;&#x25BC;</span></th>
    <th onclick="sortTable(4)">Delegated Permissions <span class="sort-arrow">&#x25B2;&#x25BC;</span></th>
    <th onclick="sortTable(5)">Application Permissions <span class="sort-arrow">&#x25B2;&#x25BC;</span></th>
</tr>
</thead>
<tbody>
"@

foreach ($row in $reportRows) {
    $nameHtml = [System.Net.WebUtility]::HtmlEncode($row.DisplayName)
    $appIdHtml = [System.Net.WebUtility]::HtmlEncode($row.AppId)
    $audienceHtml = [System.Net.WebUtility]::HtmlEncode($row.SignInAudience)

    # Build permission tag HTML
    if ($row.DelegatedPerms) {
        $delHtml = ($row.DelegatedPerms -split ", " | ForEach-Object {
            "<span class='perm-tag perm-delegated'>$([System.Net.WebUtility]::HtmlEncode($_))</span>"
        }) -join " "
    } else {
        $delHtml = "<span class='perm-none'>None</span>"
    }

    if ($row.ApplicationPerms) {
        $appHtml = ($row.ApplicationPerms -split ", " | ForEach-Object {
            "<span class='perm-tag perm-application'>$([System.Net.WebUtility]::HtmlEncode($_))</span>"
        }) -join " "
    } else {
        $appHtml = "<span class='perm-none'>None</span>"
    }

    # Count badges
    $badges = ""
    if ($row.DelegatedCount -gt 0)   { $badges += "<span class='badge badge-del'>$($row.DelegatedCount) delegated</span>" }
    if ($row.ApplicationCount -gt 0) { $badges += "<span class='badge badge-app'>$($row.ApplicationCount) application</span>" }

    $html += @"

<tr>
    <td><strong>$nameHtml</strong>$badges</td>
    <td style="font-family:monospace;font-size:0.8rem;">$appIdHtml</td>
    <td>$audienceHtml</td>
    <td>$($row.Created)</td>
    <td>$delHtml</td>
    <td>$appHtml</td>
</tr>
"@
}

$html += @"

</tbody>
</table>

<footer>Data sourced from Microsoft Graph &bull; Report generated by Get-AppRegistrationReport.ps1</footer>

<script>
// Live search / filter
document.getElementById('search').addEventListener('input', function () {
    const q = this.value.toLowerCase();
    document.querySelectorAll('#reportTable tbody tr').forEach(tr => {
        tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
});

// Column sort
let sortDir = {};
function sortTable(col) {
    const table = document.getElementById('reportTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    sortDir[col] = !sortDir[col];
    rows.sort((a, b) => {
        const at = a.children[col].textContent.trim().toLowerCase();
        const bt = b.children[col].textContent.trim().toLowerCase();
        return sortDir[col] ? at.localeCompare(bt) : bt.localeCompare(at);
    });
    rows.forEach(r => tbody.appendChild(r));
}
</script>
</body>
</html>
"@

# ── 7. Write report ───────────────────────────────────────────────────────
$html | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Green
Write-Host "Open it in a browser to view." -ForegroundColor Cyan

# ── 8. Disconnect ─────────────────────────────────────────────────────────
Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Gray

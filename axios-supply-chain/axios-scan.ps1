# axios-scan.ps1 — Scan for compromised axios versions (axios supply-chain attack, 2026-03-30)
# Affected: axios@1.14.1, axios@0.30.4 | Malicious dep: plain-crypto-js@4.2.1
# Safe versions: axios@1.14.0 (1.x branch), axios@0.30.3 (0.x branch)
#
# Run as Administrator for automatic firewall blocking.
# Usage: pwsh -ExecutionPolicy Bypass -File .\axios-scan.ps1

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$AffectedAxiosVersions = @('1.14.1', '0.30.4')
$C2IP                  = '142.11.206.73'
$C2Domain              = 'sfrclak.com'
$ScanRoot              = $env:USERPROFILE

$foundAffected = $false
$foundRAT      = $false

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Banner {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   axios Supply-Chain Attack Scanner (2026-03-30)     ║" -ForegroundColor Cyan
    Write-Host "║   Scanning: $ScanRoot" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-CredentialRotationWarning {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║  ⚠  CRITICAL: ROTATE ALL CREDENTIALS IMMEDIATELY               ║" -ForegroundColor Red
    Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
    Write-Host "║  A compromised axios version was found. The malware drops a RAT  ║" -ForegroundColor Red
    Write-Host "║  that exfiltrates secrets. Assume full system compromise.        ║" -ForegroundColor Red
    Write-Host "║                                                                  ║" -ForegroundColor Red
    Write-Host "║  Rotate NOW:                                                     ║" -ForegroundColor Red
    Write-Host "║   SSH keys      : revoke & regenerate all keypairs (~/.ssh/)     ║" -ForegroundColor Red
    Write-Host "║   Git tokens    : GitHub / GitLab / Bitbucket PATs               ║" -ForegroundColor Red
    Write-Host "║   npm tokens    : .npmrc tokens / Artifactory / Nexus            ║" -ForegroundColor Red
    Write-Host "║   Cloud creds   : AWS, Azure, GCP — rotate IAM keys/svc accounts ║" -ForegroundColor Red
    Write-Host "║   DB passwords  : Postgres, MySQL, MongoDB, Redis, etc.          ║" -ForegroundColor Red
    Write-Host "║   CI/CD secrets : GitHub Actions, GitLab CI, Azure DevOps vars   ║" -ForegroundColor Red
    Write-Host "║   .env files    : all API keys, secrets, connection strings       ║" -ForegroundColor Red
    Write-Host "║   Docker Hub    : container registry credentials                 ║" -ForegroundColor Red
    Write-Host "║   Shell history : tokens cached in PowerShell history/profiles   ║" -ForegroundColor Red
    Write-Host "║                                                                  ║" -ForegroundColor Red
    Write-Host "║  C2 seen at: sfrclak.com:8000 / 142.11.206.73                   ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""

    Write-Host "[*] Attempting to block C2 IP in Windows Firewall..." -ForegroundColor Yellow
    try {
        $ruleExists = Get-NetFirewallRule -DisplayName "BLOCK-axios-C2-$C2IP" -ErrorAction SilentlyContinue
        if (-not $ruleExists) {
            New-NetFirewallRule `
                -DisplayName "BLOCK-axios-C2-$C2IP" `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $C2IP `
                -Protocol Any `
                -ErrorAction Stop | Out-Null
            Write-Host "    [+] Outbound firewall rule created to block $C2IP" -ForegroundColor Green
        } else {
            Write-Host "    [i] Firewall rule already exists for $C2IP" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [!] Run as Administrator to auto-block. Manual command:" -ForegroundColor Yellow
        Write-Host "        New-NetFirewallRule -DisplayName 'BLOCK-C2' -Direction Outbound -Action Block -RemoteAddress $C2IP" -ForegroundColor Yellow
    }
}

function Get-PackageManager {
    param([string]$ProjectDir)
    if (Test-Path (Join-Path $ProjectDir "pnpm-lock.yaml")) { return "pnpm" }
    if (Test-Path (Join-Path $ProjectDir "yarn.lock"))      { return "yarn" }
    if (Test-Path (Join-Path $ProjectDir "package-lock.json")) { return "npm" }
    if (Get-Command pnpm -ErrorAction SilentlyContinue) { return "pnpm" }
    if (Get-Command yarn -ErrorAction SilentlyContinue) { return "yarn" }
    return "npm"
}

function Get-PackageVersion {
    param([string]$PackageJsonPath)
    if (-not (Test-Path $PackageJsonPath)) { return $null }
    try {
        return (Get-Content $PackageJsonPath -Raw | ConvertFrom-Json).version
    } catch { return $null }
}

function Get-DeclaredAxiosVersion {
    param([string]$PackageJsonPath)
    try {
        $pkg = Get-Content $PackageJsonPath -Raw | ConvertFrom-Json
        $v = if ($pkg.dependencies.axios) { $pkg.dependencies.axios }
             elseif ($pkg.devDependencies.axios) { $pkg.devDependencies.axios }
             else { $null }
        if ($v) { return $v -replace '^[\^~>=]+', '' }
    } catch {}
    return $null
}

function Invoke-PmList {
    param([string]$ProjectDir, [string]$PackageManager)
    if (-not (Get-Command $PackageManager -ErrorAction SilentlyContinue)) { return $null }
    if (-not (Test-Path (Join-Path $ProjectDir "node_modules"))) { return $null }
    try {
        $output = switch ($PackageManager) {
            "pnpm" { & pnpm list axios --dir $ProjectDir 2>$null }
            "yarn" { & yarn --cwd $ProjectDir list --pattern axios 2>$null }
            default { & npm list axios --prefix $ProjectDir 2>$null }
        }
        $match = $output | Select-String -Pattern '(\d+\.\d+\.\d+)' | Select-Object -First 1
        if ($match -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    } catch {}
    return $null
}

function Set-AxiosOverride {
    param([string]$PackageJsonPath, [string]$SafeVersion)

    # Check if overrides.axios is already set correctly
    try {
        $existing = (Get-Content $PackageJsonPath -Raw | ConvertFrom-Json).overrides.axios
        if ($existing -eq $SafeVersion) {
            Write-Host "    [i] overrides.axios already set to $SafeVersion in $PackageJsonPath" -ForegroundColor Green
            return
        }
    } catch {}

    # Prefer jq: JSON-native tool that preserves arrays, formatting, and all field types
    if (Get-Command jq -ErrorAction SilentlyContinue) {
        try {
            $tmp = "$PackageJsonPath.tmp"
            & jq --arg v $SafeVersion '.overrides.axios = $v' $PackageJsonPath | Set-Content $tmp -Encoding UTF8
            Move-Item $tmp $PackageJsonPath -Force
            Write-Host "    [+] Injected overrides.axios = `"$SafeVersion`" into $PackageJsonPath" -ForegroundColor Green
            return
        } catch {
            Remove-Item "$PackageJsonPath.tmp" -ErrorAction SilentlyContinue
        }
    }

    # Fallback: PowerShell round-trip. Note: single-element arrays in package.json
    # (e.g. "keywords": ["foo"]) may be flattened to scalars by ConvertTo-Json.
    # Install jq to avoid this. https://jqlang.org/download/
    try {
        $pkg = Get-Content $PackageJsonPath -Raw | ConvertFrom-Json
        if ($null -eq $pkg.overrides) {
            $pkg | Add-Member -MemberType NoteProperty -Name overrides -Value ([PSCustomObject]@{}) -Force
        }
        $pkg.overrides | Add-Member -MemberType NoteProperty -Name axios -Value $SafeVersion -Force
        $pkg | ConvertTo-Json -Depth 10 | Set-Content $PackageJsonPath -Encoding UTF8
        Write-Host "    [+] Injected overrides.axios = `"$SafeVersion`" into $PackageJsonPath" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not auto-inject overrides — add manually to $PackageJsonPath :" -ForegroundColor Yellow
        Write-Host "        `"overrides`": { `"axios`": `"$SafeVersion`" }" -ForegroundColor Yellow
    }
}

# ─── Preflight: dependency check ──────────────────────────────────────────────

function Write-Preflight {
    Write-Host "[*] Dependency check:" -ForegroundColor Cyan

    $anyPm = $false
    foreach ($pm in @("pnpm", "yarn", "npm")) {
        if (Get-Command $pm -ErrorAction SilentlyContinue) {
            Write-Host "    $($pm.PadRight(7)) + found" -ForegroundColor Green
            $anyPm = $true
        } else {
            Write-Host "    $($pm.PadRight(7)) x missing" -ForegroundColor DarkGray
        }
    }
    if (-not $anyPm) {
        Write-Host "    No package manager found — version detection will use file fallback only" -ForegroundColor Yellow
    }

    if (Get-Command jq -ErrorAction SilentlyContinue) {
        Write-Host "    jq      + found — overrides injection will preserve package.json exactly" -ForegroundColor Green
    } else {
        Write-Host "    jq      x missing — overrides injection will use PowerShell fallback" -ForegroundColor Yellow
        Write-Host "             WARNING: single-element arrays in package.json may be corrupted" -ForegroundColor Red
        Write-Host "             Install jq to avoid this: https://jqlang.org/download/" -ForegroundColor Yellow
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if ($isAdmin) {
        Write-Host "    admin   + running as Administrator — firewall auto-block enabled" -ForegroundColor Green
    } else {
        Write-Host "    admin   x not Administrator — C2 firewall block will require manual step" -ForegroundColor Yellow
    }

    Write-Host ""
}

# ─── 1. Active C2 connection check ────────────────────────────────────────────

Write-Banner
Write-Preflight

Write-Host "[*] Checking for active C2 connections to $C2Domain / $C2IP..." -ForegroundColor Cyan
$activeConns = Get-NetTCPConnection -RemoteAddress $C2IP -ErrorAction SilentlyContinue
if ($activeConns) {
    Write-Host "[!!!] LIVE C2 CONNECTION DETECTED — system is actively compromised!" -ForegroundColor Red
    $foundRAT = $true
} else {
    Write-Host "    [OK] No active connection to C2 address." -ForegroundColor Green
}
Write-Host ""

# ─── 2. Scan Node.js projects ─────────────────────────────────────────────────

Write-Host "[*] Scanning $ScanRoot for Node.js projects..." -ForegroundColor Cyan

$packageFiles = Get-ChildItem -Path $ScanRoot -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\.git\\' }

Write-Host "[*] Found $($packageFiles.Count) project package.json file(s). Inspecting..." -ForegroundColor Cyan
Write-Host ""

foreach ($pkgFile in $packageFiles) {
    $projectDir = $pkgFile.DirectoryName

    # ── Detect package manager and installed axios version ───────────────────
    $pm = Get-PackageManager -ProjectDir $projectDir
    $installedVersion = Invoke-PmList -ProjectDir $projectDir -PackageManager $pm

    # ── Fallback: read node_modules/axios/package.json ───────────────────────
    if (-not $installedVersion) {
        $installedVersion = Get-PackageVersion -PackageJsonPath (
            Join-Path $projectDir "node_modules\axios\package.json"
        )
    }

    # ── Declared version (no node_modules) ───────────────────────────────────
    $declaredVersion = $null
    if (-not $installedVersion) {
        $declaredVersion = Get-DeclaredAxiosVersion -PackageJsonPath $pkgFile.FullName
    }

    # ── Check for malicious plain-crypto-js ──────────────────────────────────
    $ratPkgPath = Join-Path $projectDir "node_modules\plain-crypto-js"
    $ratPresent = Test-Path $ratPkgPath
    if ($ratPresent) {
        Write-Host "[CRITICAL]  $projectDir" -ForegroundColor Red
        Write-Host "  plain-crypto-js : found in node_modules — RAT dropper present!" -ForegroundColor Red
        $foundRAT = $true
    }

    $projectFlagged = $false
    $safeVersion = "1.14.0"

    if ($installedVersion -and $AffectedAxiosVersions -contains $installedVersion) {
        Write-Host "[INFECTED]  $projectDir" -ForegroundColor Red
        Write-Host "  axios installed : $installedVersion (AFFECTED)" -ForegroundColor Red
        $foundAffected = $true
        $projectFlagged = $true
        $safeVersion = if ($installedVersion -like "0.*") { "0.30.3" } else { "1.14.0" }
    } elseif ($declaredVersion -and $AffectedAxiosVersions -contains $declaredVersion) {
        Write-Host "[WARNING]   $projectDir" -ForegroundColor Yellow
        Write-Host "  axios declared  : $declaredVersion (run $pm install to confirm)" -ForegroundColor Yellow
        $foundAffected = $true
        $projectFlagged = $true
        $safeVersion = if ($declaredVersion -like "0.*") { "0.30.3" } else { "1.14.0" }
    }

    if ($projectFlagged -or $ratPresent) {
        Write-Host "  Project file    : $($pkgFile.FullName)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Mitigation steps ($pm project):" -ForegroundColor Yellow
        Write-Host "  1. cd `"$projectDir`""
        switch ($pm) {
            "pnpm" { Write-Host "  2. pnpm add axios@$safeVersion" }
            "yarn" { Write-Host "  2. yarn add axios@$safeVersion" }
            default { Write-Host "  2. npm install axios@$safeVersion" }
        }
        Write-Host "  3. Remove-Item -Recurse -Force `"$ratPkgPath`""
        switch ($pm) {
            "pnpm" { Write-Host "  4. pnpm install --ignore-scripts" }
            "yarn" { Write-Host "  4. yarn install --ignore-scripts" }
            default { Write-Host "  4. npm install --ignore-scripts" }
        }
        Write-Host ""
        Set-AxiosOverride -PackageJsonPath $pkgFile.FullName -SafeVersion $safeVersion
        Write-Host ""
    }
}

# ─── Summary ──────────────────────────────────────────────────────────────────

Write-Host "────────────────────────────────────────────────────────" -ForegroundColor DarkGray

if (-not $foundAffected -and -not $foundRAT) {
    Write-Host "[OK] No affected axios versions or malicious packages found." -ForegroundColor Green
    Write-Host "     Consider pinning axios via package.json overrides as a precaution." -ForegroundColor Green
} else {
    Write-CredentialRotationWarning
}

Write-Host "────────────────────────────────────────────────────────" -ForegroundColor DarkGray

<#
  FAIR Risk Platform - Windows developer workstation setup
  Installs the toolchain needed to build and test locally (ADR-003 stack):
    Git, GitHub CLI, Go, Python 3.12, Node.js LTS, WSL2 + Docker Desktop,
    kubectl, kind, Helm, plus Go-based CI tools (golangci-lint, syft, cosign).
  Postgres 16, NATS JetStream and the OTel collector run as containers, not native installs.

  Run from an elevated PowerShell:
    powershell -ExecutionPolicy Bypass -File .\tools\dev-setup\install-dev-tools.ps1
  Safe to re-run: already-installed packages are skipped.
  Writes a log and a version report next to this script.
#>
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$log  = Join-Path $here 'install-log.txt'
$report = Join-Path $here 'versions.txt'
Start-Transcript -Path $log -Force | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning 'Not elevated. Re-run from "Run as administrator" PowerShell (needed for WSL/Docker).'; Stop-Transcript | Out-Null; exit 1 }

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
  Write-Error 'winget not found. Install "App Installer" from the Microsoft Store, then re-run.'; Stop-Transcript | Out-Null; exit 1
}

# 1. WSL2 (Docker Desktop backend)
Write-Host "`n== WSL2 ==" -ForegroundColor Cyan
$wslOk = $false
try { wsl --status *> $null; if ($LASTEXITCODE -eq 0) { $wslOk = $true } } catch {}
if ($wslOk) { Write-Host 'WSL already present; updating.'; wsl --update }
else { Write-Host 'Installing WSL2 (a reboot will be required).'; wsl --install --no-distribution; $script:rebootNeeded = $true }

# 2. winget packages
$packages = @(
  'Git.Git',
  'GitHub.cli',
  'GoLang.Go',
  'Python.Python.3.12',
  'OpenJS.NodeJS.LTS',
  'Docker.DockerDesktop',
  'Kubernetes.kubectl',
  'Kubernetes.kind',
  'Helm.Helm'
)
foreach ($id in $packages) {
  Write-Host "`n== $id ==" -ForegroundColor Cyan
  winget list --id $id --exact --accept-source-agreements *> $null
  if ($LASTEXITCODE -eq 0) { Write-Host "$id already installed - checking for upgrade."; winget upgrade --id $id --exact --silent --accept-package-agreements --accept-source-agreements }
  else { winget install --id $id --exact --silent --accept-package-agreements --accept-source-agreements }
  if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) { Write-Warning "$id returned exit code $LASTEXITCODE" }
}

# Refresh PATH for this session
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
$goBin = Join-Path $env:USERPROFILE 'go\bin'
if ($env:Path -notlike "*$goBin*") { $env:Path += ";$goBin" }

# 3. Go-based CI tools (match CI: lint, SBOM, signing)
Write-Host "`n== Go CI tools ==" -ForegroundColor Cyan
if (Get-Command go -ErrorAction SilentlyContinue) {
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
  go install github.com/anchore/syft/cmd/syft@latest
  go install github.com/sigstore/cosign/v2/cmd/cosign@latest
  $userPath = [Environment]::GetEnvironmentVariable('Path','User')
  if ($userPath -notlike "*$goBin*") { [Environment]::SetEnvironmentVariable('Path', "$userPath;$goBin", 'User') }
} else { Write-Warning 'go not on PATH yet - open a new terminal and re-run this script to install the Go tools.' }

# 4. Version report
Write-Host "`n== Versions ==" -ForegroundColor Cyan
$checks = [ordered]@{
  'git'='git --version'; 'gh'='gh --version'; 'go'='go version'; 'python'='python --version';
  'node'='node --version'; 'npm'='npm --version'; 'docker'='docker --version'; 'kubectl'='kubectl version --client';
  'kind'='kind version'; 'helm'='helm version --short'; 'golangci-lint'='golangci-lint --version';
  'syft'='syft version'; 'cosign'='cosign version'; 'wsl'='wsl --version'
}
$out = @("Generated $(Get-Date -Format s) on $env:COMPUTERNAME")
foreach ($k in $checks.Keys) {
  try { $v = (Invoke-Expression $checks[$k] 2>&1 | Select-Object -First 1) } catch { $v = 'NOT FOUND' }
  if (-not $v) { $v = 'NOT FOUND' }
  $out += ('{0,-14} {1}' -f $k, $v)
}
$out | Tee-Object -FilePath $report

Write-Host "`nDone. Log: $log" -ForegroundColor Green
if ($script:rebootNeeded) { Write-Host 'REBOOT REQUIRED for WSL2, then start Docker Desktop once and re-run this script.' -ForegroundColor Yellow }
else { Write-Host 'Start Docker Desktop once (accept its terms) so the docker engine is running.' -ForegroundColor Yellow }
Stop-Transcript | Out-Null

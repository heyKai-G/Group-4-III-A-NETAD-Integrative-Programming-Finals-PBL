<#
  Lab IDS - one-time setup (run in PowerShell as Administrator, from this folder):
      Set-ExecutionPolicy -Scope Process Bypass
      .\setup.ps1
  It: checks Python, creates .venv and installs packages, creates the PostgreSQL
  database, writes .env, makes the HTTPS certificate, creates the tables and opens
  the firewall for your lab subnet. Safe to run again.
#>
param(
    [string]$LabSubnet = "",
    [int]$Port = 5443
)
# Native tools (pip, psql) print notices on stderr; we check $LASTEXITCODE ourselves.
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Fail "Please run PowerShell as Administrator (right-click -> Run as administrator)." }

# ---- 1. Python -------------------------------------------------------------
Step "Checking Python"
$py = $null
foreach ($cand in @("python", "py")) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) { $py = $cand; break }
}
if (-not $py) { Fail "Python was not found. Install it from python.org and tick 'Add python.exe to PATH'." }
$ver = & $py --version 2>&1
Write-Host $ver
$m = [regex]::Match("$ver", "(\d+)\.(\d+)")
if ($m.Success -and ([int]$m.Groups[1].Value -eq 3) -and ([int]$m.Groups[2].Value -ge 15)) {
    Write-Host "Note: Python 3.15 is very new. If a package fails to install below, install Python 3.13" -ForegroundColor Yellow
    Write-Host "      from python.org (it can live next to 3.15), then run:  py -3.13 -m venv .venv  and re-run this script." -ForegroundColor Yellow
}

# ---- 2. Virtual environment + packages --------------------------------------
Step "Creating virtual environment and installing packages"
if (-not (Test-Path ".venv\Scripts\python.exe")) { & $py -m venv .venv; if ($LASTEXITCODE) { Fail "Could not create the virtual environment." } }
$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install -r requirements.txt
if ($LASTEXITCODE) { Fail "pip install failed. Read the message above (see the Python 3.15 note)." }

# ---- 3. PostgreSQL ---------------------------------------------------------
Step "Looking for PostgreSQL"
$psql = (Get-Command psql -ErrorAction SilentlyContinue).Source
if (-not $psql) {
    $psql = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\psql.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $psql) {
    Write-Host "PostgreSQL is not installed yet." -ForegroundColor Yellow
    Write-Host "Install it first (README, step 2), then run .\setup.ps1 again."
    exit 2
}
Write-Host "Found $psql"

$envPath = Join-Path $PSScriptRoot ".env"
$existing = @{}
if (Test-Path $envPath) {
    Get-Content $envPath | ForEach-Object { if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $existing[$Matches[1]] = $Matches[2] } }
}

if (-not $existing.ContainsKey("DATABASE_URL")) {
    $sec = Read-Host "Enter the password you chose for the PostgreSQL 'postgres' user during its installation" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    $adminPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $chars = (48..57) + (65..90) + (97..122)
    $dbPw = -join ((1..28) | ForEach-Object { [char]($chars | Get-Random) })
    $env:PGPASSWORD = $adminPw
    $hasRole = & $psql -U postgres -h localhost -tAc "SELECT 1 FROM pg_roles WHERE rolname='lab_ids'"
    if ($LASTEXITCODE) { Fail "Could not log in to PostgreSQL as 'postgres'. Check the password and that the PostgreSQL service is running." }
    if ("$hasRole".Trim() -eq "1") { & $psql -U postgres -h localhost -c "ALTER ROLE lab_ids WITH LOGIN PASSWORD '$dbPw'" | Out-Null }
    else { & $psql -U postgres -h localhost -c "CREATE ROLE lab_ids WITH LOGIN PASSWORD '$dbPw'" | Out-Null }
    $hasDb = & $psql -U postgres -h localhost -tAc "SELECT 1 FROM pg_database WHERE datname='lab_ids'"
    if ("$hasDb".Trim() -ne "1") { & $psql -U postgres -h localhost -c "CREATE DATABASE lab_ids OWNER lab_ids" | Out-Null }
    Remove-Item Env:PGPASSWORD
    $existing["DATABASE_URL"] = "postgresql+pg8000://lab_ids:$dbPw@localhost:5432/lab_ids"
    Write-Host "Database 'lab_ids' is ready."
} else { Write-Host "DATABASE_URL already in .env - keeping it." }

# ---- 4. .env ---------------------------------------------------------------
Step "Writing .env"
if (-not $existing.ContainsKey("SECRET_KEY")) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $existing["SECRET_KEY"] = -join ($bytes | ForEach-Object { $_.ToString("x2") })
}
$defaults = [ordered]@{
    EVE_JSON_PATH = "C:\Program Files\Suricata\log\eve.json"
    SURICATA_EXE  = "C:\Program Files\Suricata\suricata.exe"
    SURICATA_YAML = "C:\Program Files\Suricata\suricata.yaml"
    BIND_HOST = "0.0.0.0"; HTTPS_PORT = "$Port"; SESSION_MINUTES = "15"
    RETENTION_DAYS = "90"; APP_TZ = "Asia/Manila"
}
foreach ($k in $defaults.Keys) { if (-not $existing.ContainsKey($k)) { $existing[$k] = $defaults[$k] } }
$lines = @("# written by setup.ps1")
foreach ($k in @("SECRET_KEY", "DATABASE_URL") + @($defaults.Keys)) { $lines += "$k=$($existing[$k])" }
# optional settings you added by hand (email reset link) are kept when setup is re-run
foreach ($k in @("PUBLIC_URL", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_SECURITY", "RESET_LINK_MINUTES")) {
    if ($existing.ContainsKey($k)) { $lines += "$k=$($existing[$k])" }
}
Set-Content -Path $envPath -Value $lines -Encoding ASCII
Write-Host ".env written."

# ---- 5. Certificate + tables -----------------------------------------------
Step "Creating the HTTPS certificate"
if (-not (Test-Path "certs\server.crt")) { & $venvPy tools\make_cert.py; if ($LASTEXITCODE) { Fail "Certificate creation failed." } }
else { Write-Host "certs\server.crt already exists - keeping it." }

Step "Creating database tables"
& $venvPy manage.py init-db
if ($LASTEXITCODE) { Fail "Could not create the tables. Is the PostgreSQL service running?" }

# ---- 6. Firewall -----------------------------------------------------------
Step "Windows Firewall rule for the dashboard"
if (-not $LabSubnet) { $LabSubnet = Read-Host "Lab subnet that may open the dashboard (e.g. 192.168.1.0/24)" }
if ($LabSubnet -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { Fail "That is not a valid subnet like 192.168.1.0/24." }
Get-NetFirewallRule -DisplayName "Lab IDS dashboard" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "Lab IDS dashboard" -Direction Inbound -Protocol TCP -LocalPort $Port `
    -RemoteAddress $LabSubnet -Action Allow -Profile Any -ErrorAction Stop | Out-Null
Write-Host "Allowed TCP $Port from $LabSubnet only."

Write-Host "`nSetup finished." -ForegroundColor Green
Write-Host "Next: install Suricata + Npcap (README step 3), then run  .\start_all.ps1"

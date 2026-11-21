# Starts Suricata on the adapter you chose in the setup wizard (Administrator needed).
# Re-run it after changing settings so Suricata loads the regenerated rules.
param([string]$Interface = "")
Set-Location $PSScriptRoot
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this window as Administrator." -ForegroundColor Red; exit 1 }
$py = ".\.venv\Scripts\python.exe"
if (-not $Interface) { $Interface = (& $py tools\print_config.py suricata-iface); if ($LASTEXITCODE) { exit 1 } }
$exe  = "C:\Program Files\Suricata\suricata.exe"
$yaml = "C:\Program Files\Suricata\suricata.yaml"
foreach ($line in Get-Content .env) {
    if ($line -match '^SURICATA_EXE=(.*)$')  { $exe  = $Matches[1] }
    if ($line -match '^SURICATA_YAML=(.*)$') { $yaml = $Matches[1] }
}
if (-not (Test-Path $exe)) { Write-Host "Suricata not found at $exe - install it (README step 3)." -ForegroundColor Red; exit 1 }
Write-Host "Starting Suricata on $Interface"
& $exe -c $yaml -i $Interface

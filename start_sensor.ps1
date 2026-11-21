# Starts the sensor (device inventory, ARP/DHCP/DNS/port-scan detection, alert import).
# Needs Administrator rights for packet capture. Leave the window open.
Set-Location $PSScriptRoot
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this window as Administrator." -ForegroundColor Red; exit 1 }
& ".\.venv\Scripts\python.exe" run_sensor.py

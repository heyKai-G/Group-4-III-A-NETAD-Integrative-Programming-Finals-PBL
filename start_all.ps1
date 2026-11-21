# Opens three PowerShell windows: Suricata, the sensor and the dashboard.
# Run this from an Administrator PowerShell.
$here = $PSScriptRoot
foreach ($s in @("start_web.ps1", "start_sensor.ps1", "start_suricata.ps1")) {
    Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$here\$s`""
    Start-Sleep -Seconds 2
}
Write-Host "Started. Open https://localhost:5443 in your browser."
Write-Host "If this is the first run, Suricata will say the wizard is not finished - finish it in the browser, then run start_suricata.ps1."

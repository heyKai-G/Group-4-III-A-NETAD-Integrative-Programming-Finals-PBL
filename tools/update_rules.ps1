<#
  Downloads the free Emerging Threats Open rules that match your Suricata version and
  builds ONE rules file (suricata.rules) for Suricata. Needed because suricata-update
  is not part of the Windows installer.

  Run in PowerShell (Administrator) from the project folder:
      .\tools\update_rules.ps1

  Offline (archive copied over by USB):
      .\tools\update_rules.ps1 -Archive D:\emerging-all.rules.tar.gz
#>
param(
    [string]$Archive = "",
    [string]$SuricataExe = "C:\Program Files\Suricata\suricata.exe",
    [string]$OutDir = ""
)
$ErrorActionPreference = "Stop"
$project = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $project "suricata\et-rules" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $Archive) {
    if (-not (Test-Path $SuricataExe)) { throw "Suricata not found at $SuricataExe. Use -SuricataExe to give its path." }
    $text = (& $SuricataExe -V 2>&1 | Out-String)
    $m = [regex]::Match($text, 'version\s+(\d+\.\d+\.\d+)')
    if (-not $m.Success) { throw "Could not read the Suricata version from: $text" }
    $ver = $m.Groups[1].Value
    Write-Host "Suricata version $ver"
    $Archive = Join-Path $OutDir "emerging-all.rules.tar.gz"
    $ok = $false
    foreach ($scheme in @("https", "http")) {
        $url = "${scheme}://rules.emergingthreats.net/open/suricata-$ver/emerging-all.rules.tar.gz"
        try {
            Invoke-WebRequest -Uri $url -OutFile $Archive -UseBasicParsing
            Write-Host "Downloaded $url"
            $ok = $true
            break
        } catch {
            Write-Host "Could not download $url  ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }
    if (-not $ok) {
        throw "Download failed. Check the internet connection, or download emerging-all.rules.tar.gz for Suricata $ver on another PC and run this script with -Archive."
    }
}
if (-not (Test-Path $Archive)) { throw "Archive not found: $Archive" }

$extract = Join-Path $OutDir "extracted"
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
New-Item -ItemType Directory -Force -Path $extract | Out-Null
tar -xzf $Archive -C $extract
if ($LASTEXITCODE -ne 0) { throw "Could not unpack the archive with tar." }

$files = @(Get-ChildItem $extract -Recurse -Filter "*.rules")
if ($files.Count -eq 0) { throw "No .rules files were found inside the archive." }

# Join the raw bytes (no re-encoding, no BOM) into a single file.
$target = Join-Path $OutDir "suricata.rules"
$tmp = "$target.new"
if (Test-Path $tmp) { Remove-Item $tmp -Force }
$out = [IO.File]::Open($tmp, [IO.FileMode]::Create)
try {
    $nl = [byte[]](10)
    foreach ($f in $files) {
        $b = [IO.File]::ReadAllBytes($f.FullName)
        $out.Write($b, 0, $b.Length)
        $out.Write($nl, 0, 1)
    }
} finally { $out.Close() }
Move-Item $tmp $target -Force

$count = 0
foreach ($line in [IO.File]::ReadLines($target)) { if ($line.StartsWith("alert ")) { $count++ } }
Write-Host "`nDone: $count active rules from $($files.Count) files in $target" -ForegroundColor Green
$local = Join-Path $project "suricata\local.rules"
Write-Host "`nPut these lines in suricata.yaml (replace the existing default-rule-path and rule-files):`n"
Write-Host "default-rule-path: $OutDir"
Write-Host "rule-files:"
Write-Host "  - suricata.rules"
Write-Host "  - $local"
Write-Host "`nThen check it with:  & `"$SuricataExe`" -T -c `"C:\Program Files\Suricata\suricata.yaml`""

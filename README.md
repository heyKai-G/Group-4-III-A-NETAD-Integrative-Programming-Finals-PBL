# Lab IDS - web-based Intrusion Detection System

Python (Flask) + Bootstrap 5 dashboard on top of **Suricata**, with PostgreSQL storage.
Runs on Windows 11, no Docker, and works fully offline once installed (Bootstrap and Chart.js are bundled).

**Detect-only.** It raises alerts; it never blocks anything.

## How it works

```
 Old PLDT router --- [built-in Ethernet] IDS LAPTOP [USB-Ethernet adapter] --- switch --- lab devices
                                          |
              Suricata  (signatures + thresholds: brute force, floods, scans, malware)
              Sensor    (ARP spoofing, rogue DHCP, DNS tunnelling, port scans, device list, traffic)
                                          |
                      PostgreSQL  <---  Flask dashboard (HTTPS, login + 2FA)
```

| Part | Detects / does |
|---|---|
| **Suricata** + Emerging Threats Open rules | malware/C2 signatures, exploits, scans, plus my local rules |
| Local rules (generated for you) | SSH/FTP/Telnet/RDP connection bursts, FTP/Telnet/HTTP failed-login floods, HTTP login floods, Xmas/NULL/FIN scans, SYN/UDP/ICMP floods, EICAR test file, outbound connections to reverse-shell/IRC ports |
| **Sensor** (Python + Scapy) | ARP spoofing (gateway MAC change, MAC change, ARP storms), rogue DHCP server, port scans (distinct ports), DNS anomalies (long names, random-looking names, many unique sub-domains, TXT/NULL bursts), device inventory, traffic charts |
| **Dashboard** | live traffic chart, alert feed, filters, device list, network map, CSV/PDF export, light/dark theme |

Alerts are deleted after 90 days (`RETENTION_DAYS`). Traffic samples after 7 days.

## What it can and cannot see (read this first)

An IDS only sees packets that physically pass the capture adapter. Your router has no port mirroring, so the laptop sits **in the path** (a Windows network bridge).

* You **monitor the adapter that faces the switch** (the USB-Ethernet adapter).
* That adapter sees everything that crosses between the *switch side* and the *router side*, plus broadcasts.
* **Every attack you want detected must have at least one end on the switch side**:
  * Kali on the switch attacking the IDS laptop's own services (simplest first test), or
  * Kali on the switch attacking something on the router side, or
  * Kali on the router side (router's LAN port/Wi-Fi) attacking a device on the switch.
* **Two devices plugged into the same switch talk directly through the switch. The laptop never sees that traffic.** Do not test with attacker and victim on the same switch.
* Something on the router's own Wi-Fi attacking the IDS laptop itself arrives on the *other* adapter (built-in port) and is **not** seen. Keep the attacker on the switch for the first tests.
* Windows can only bridge wired adapters, not Wi-Fi. Turn Wi-Fi off in the lab.
* The LS1008 is (as far as I know) a 10/100 switch. Fine for detection; a flood test can saturate it.

---

## Step 1 - Cabling and the Windows bridge

1. Old PLDT router -> cable -> IDS laptop's **built-in Ethernet** port.
2. IDS laptop's **USB-Ethernet adapter** -> cable -> the switch.
3. Everything lab-side (Kali laptop, target devices) -> switch.
4. Plug in the USB adapter while the laptop still has internet so Windows can download its driver. Check **Device Manager -> Network adapters**: no yellow warning.
5. Press `Win+R`, type `ncpa.cpl`, Enter. Select **both** wired adapters (Ctrl+click), right-click -> **Bridge Connections**. A "Network Bridge" appears and gets the IP from the router.
6. Test: from the Kali laptop (on the switch) you should get an IP from the PLDT router and be able to ping the router.

Do the internet-requiring installs (steps 2-3) first, on your other router, then move the laptop to the lab.

## Step 2 - Install PostgreSQL

1. Download the Windows installer from <https://www.postgresql.org/download/windows/> and run it with the defaults (port **5432**).
2. Set a password for the `postgres` user and **remember it**; `setup.ps1` asks for it once to create the `lab_ids` database and user (it generates a separate random password for the app and stores it in `.env`).

## Step 3 - Npcap and Suricata

**Npcap** (you may already have it from Nmap). Check in an Administrator Command Prompt:

```
sc query npcap
```

`STATE ... RUNNING` means it is installed. Guides for Suricata on Windows say to install Npcap with the **"WinPcap API-compatible Mode"** option. If Suricata later refuses to start, reinstall the current Npcap from <https://npcap.com> with that box ticked.

**Suricata**

1. Download the Windows installer (MSI) from the official page <https://suricata.io/download/> and install it (default folder is normally `C:\Program Files\Suricata`).
2. Rules: **`suricata-update` is not part of the Windows installer** (the Suricata developers say it is not well tested on Windows), so use the included script. It reads your Suricata version, downloads the matching free Emerging Threats Open rules from `rules.emergingthreats.net`, and joins them into one file. In PowerShell as Administrator:

   ```powershell
   cd C:\lab-ids
   Set-ExecutionPolicy -Scope Process Bypass
   .\tools\update_rules.ps1
   ```

   It prints the exact `default-rule-path` and `rule-files` lines for step 3. Without internet, download `emerging-all.rules.tar.gz` for your version on another PC and run `.\tools\update_rules.ps1 -Archive D:\emerging-all.rules.tar.gz`. Re-run it now and then to refresh the rules. The full rule set makes Suricata start slower and use more memory.
3. Edit `suricata.yaml` (Notepad, as Administrator). Make these changes:

   ```yaml
   vars:
     address-groups:
       HOME_NET: "[192.168.1.0/24]"     # your lab subnet - the web app shows the exact value in Settings

   default-rule-path: C:\lab-ids\suricata\et-rules      # printed by update_rules.ps1
   rule-files:
     - suricata.rules
     - C:\lab-ids\suricata\local.rules    # generated by the web app after the wizard

   # in the outputs: section, keep eve-log enabled and make sure these are listed under types:
   #   - alert
   #   - stats
   ```

   `local.rules` is created when you finish the setup wizard (step 5), so add that line after the wizard.
4. Check the file: `suricata.exe -T -c "C:\Program Files\Suricata\suricata.yaml"`. It must end without errors. If it complains about a rule line, send me the message.
5. Suricata must run **as Administrator**, otherwise it cannot write `eve.json` ("Permission denied").

## Step 4 - Install the dashboard

1. Copy this folder to the IDS laptop (for example `C:\lab-ids`).
2. PowerShell **as Administrator**:

   ```powershell
   cd C:\lab-ids
   Set-ExecutionPolicy -Scope Process Bypass
   .\setup.ps1
   ```

   It creates `.venv`, installs the packages, creates the database, writes `.env`, makes the HTTPS certificate, creates the tables and opens TCP 5443 in Windows Firewall **only for your lab subnet** (it asks for it).
3. If it says PostgreSQL is missing, do step 2 and run it again. If `pip install` fails on Python 3.15, install Python 3.13 from python.org (it can stay next to 3.15), run `py -3.13 -m venv .venv --clear`, and run `setup.ps1` again.

## Step 5 - First run

```powershell
.\start_all.ps1     # opens windows for the dashboard, the sensor and Suricata (as Administrator)
```

1. Open <https://localhost:5443>. The browser warns about the self-signed certificate: **Advanced -> continue** (the traffic is still encrypted). Other devices use `https://<IDS laptop IP>:5443` (`ipconfig` shows it).
2. **Create the admin account.** Registration closes after this.
3. Scan the QR code with an authenticator app and enter the 6-digit code.
4. **Setup wizard**: network name, subnet, gateway (router IP), the adapter to monitor (**the USB adapter facing the switch**), sensitivity, authorized DHCP servers.
5. Save. The app writes `suricata\local.rules`. Add it to `rule-files` (step 3.3) and restart Suricata with `.\start_suricata.ps1`.
6. The dashboard header shows **Suricata: running** and **Sensor: running** when everything is connected.

Later, stop everything with Ctrl+C in each window. Changing Settings regenerates the rules; restart Suricata afterwards.

## Step 6 - Test targets on the IDS laptop

Only start what you want to test. Replace `192.168.1.0/24` with your lab subnet.

**SSH** (Windows OpenSSH Server)

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
```

**FTP** and **web login** (included scripts):

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-targets.txt
.\.venv\Scripts\python.exe tools\targets\ftp_target.py          # port 21, labuser / lab-password-123
.\.venv\Scripts\python.exe tools\targets\web_login_target.py    # port 8080, admin / lab-password-123
```

**Firewall for the targets** (lab subnet only; remove afterwards):

```powershell
New-NetFirewallRule -DisplayName "Lab target" -Direction Inbound -Protocol TCP -LocalPort 21,22,8080 -RemoteAddress 192.168.1.0/24 -Action Allow
# remove later:
Remove-NetFirewallRule -DisplayName "Lab target"
```

## Step 7 - Attack tests from Kali (your own lab only)

Kali plugs into the **switch**. `T` = the IDS laptop's IP. Start with low rates; a flood can freeze a small laptop. Never aim these at anything that is not yours.

| Test | Command on Kali | Expect |
|---|---|---|
| Port scan | `nmap -sS -p 1-1000 T` | **Port Scan** (sensor), maybe also Suricata scan rules |
| Xmas / NULL / FIN scan | `sudo nmap -sX -p 1-100 T` (also `-sN`, `-sF`) | **Port Scan** (Suricata) |
| SSH brute force | `hydra -l admin -P pw.txt ssh://T -t 4` (use a list of 100+ passwords: SSH tries several passwords per connection, so a tiny list opens too few connections to trip the rule) | **Brute Force** (SSH connection burst) |
| FTP brute force | `hydra -l labuser -P pw.txt ftp://T -t 4` | **Brute Force** (FTP burst + failed logins) |
| HTTP login brute force | `hydra -l admin -P pw.txt -s 8080 T http-post-form "/login:user=^USER^&password=^PASS^:Invalid credentials"` | **Brute Force** (login submissions + 401s) |
| Telnet burst | `for i in $(seq 12); do nc -zv -w1 T 23; done` | **Brute Force** (Telnet burst; needs no service) |
| SYN flood | `sudo hping3 -S -p 80 -i u1000 -c 8000 T` | **DDoS** SYN flood |
| UDP flood | `sudo hping3 --udp -p 53 -i u1000 -c 8000 T` | **DDoS** UDP flood |
| ICMP flood | `sudo hping3 --icmp -i u1000 -c 4000 T` | **DDoS** ICMP flood |
| ARP spoofing (gateway claim) | `sudo arping -U -c 5 -I eth0 -S ROUTER_IP ROUTER_IP` (Thomas Habets' arping, the one Kali ships; capital `-S` sets the claimed IP) | **ARP Spoofing** (high) |
| DNS tunnelling | `for i in $(seq 60); do dig +short $(head -c 24 /dev/urandom \| base32 \| tr -d '=' \| tr A-Z a-z).t.example @ROUTER_IP; done` | **DNS Anomaly** |
| Reverse-shell port | on Kali `nc -lvnp 4444`; on a lab device `Test-NetConnection KALI_IP -Port 4444` | **Malware/C2** |

Wordlist: `printf "123456\npassword\nqwerty\nletmein\nadmin\nwelcome\nmonkey\ndragon\nsunshine\nlogin\n" > pw.txt`

Rogue DHCP: run a DHCP server (for example `dnsmasq`) on Kali on the lab network; any OFFER from an IP that is not in your authorized list raises **Rogue DHCP**. This hands out addresses, so keep it short and only in the isolated lab.

EICAR (optional): serve the standard EICAR test file from Kali (`python3 -m http.server`) and download it from a lab device. Get the file from <https://www.eicar.org>. Windows Defender may block it on the laptop; Suricata still sees the transfer. I did not put the file in this project because antivirus would delete it.

Higher sensitivity lowers the thresholds. A fast `nmap` of 1000 ports can also trip the **SYN flood** rule on *High*; that is expected.

## Using the dashboard

* **Dashboard**: stat cards, live traffic (Kbit/s on the monitored adapter), alerts per category and per hour, top sources, live alert feed, Suricata and sensor status.
* **Alerts**: filter by category, severity, engine, status, IP, text and dates; click an alert for the raw event; acknowledge; export **CSV** or **PDF** (current filters; CSV cells are protected against spreadsheet formula injection).
* **Devices**: everything the sensor learned from ARP, DHCP and traffic inside your subnet.
* **Network map**: gateway, IDS laptop and devices; red = source of alerts in the last hour, amber = target.
* **Settings**: change the network answers; shows the exact `HOME_NET`, rules path and Suricata command.
* **Users**: list accounts, create more accounts, delete an account (see below).
* **Account**: change password; make new recovery codes; recent security events (logins, failures, exports).

### Accounts, recovery codes and password reset

* **Create accounts**: *Users* page, any logged-in user can add another account (username, email, password). The new person logs in, sets up their own authenticator app and is shown their 8 recovery codes. All accounts have the same rights.
* **Delete an account**: *Users* -> Delete. You must type **your own password and a current authenticator code**. You cannot delete yourself. Wrong answers count toward the lockout.
* **Recovery codes**: 8 one-time codes (`XXXXX-XXXXX`) shown once at 2FA setup. Write them down. *Account -> Make new recovery codes* replaces the set (needs your password). **Existing users who upgraded have no codes yet: make them now.**
* **Forgot password**: login page -> *Forgot password?*. Option 1: username + a recovery code + new password. Option 2 (last resort): *email me a reset link*. The authenticator app is still needed to log in afterwards.
* **Email reset link (optional, off by default)**: needs internet on the IDS laptop and an SMTP account. Put these in `.env` and restart the dashboard: `PUBLIC_URL` (e.g. `https://192.168.1.10:5443`), `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_SECURITY` (`starttls`, `ssl` or `none`). The link is single-use, valid 30 minutes, max 3 requests per hour. `setup.ps1` keeps these lines when re-run.
* **Lost phone and no recovery codes**: `.\.venv\Scripts\python.exe manage.py reset-admin` on the laptop.
* **Upgrading an existing install**: replace the folder contents (keep `.env` and `certs`), run `.\setup.ps1` again. The two new tables are created automatically; your alerts and users are kept.

## Security features

* Argon2 password hashing; minimum 12 characters, letters and a number
* TOTP 2FA (authenticator app), codes cannot be reused; the 2FA secret is stored encrypted
* Lockout for 15 minutes after 5 failed attempts (also for unknown usernames)
* CSRF protection on every form, 15-minute inactivity session timeout, secure/HttpOnly cookies
* HTTPS (self-signed), strict Content-Security-Policy, no external scripts or fonts
* Firewall rule limited to the lab subnet; audit log of security events
* Password reset by recovery code or (optional) emailed one-time link; account deletion needs password + authenticator code
* Lost phone and no codes: on the laptop run `.\.venv\Scripts\python.exe manage.py reset-admin`

## Not included yet (and honest limits)

* **Beaconing / C2 timing analysis.** Known-bad C2 is covered by Emerging Threats rules and the port rule, but periodic "phone home" behaviour is not analysed.
* No blocking (IPS), email/Telegram alerts, or device vendor lookup.
* An IDS does not scan files or the PC for viruses; it detects malware by its **network** behaviour.
* The generated local rules use Suricata 7/8 syntax. Suricata checks them at start-up (`-T`), so a wrong line will be named in the error.
* I built and tested the web app, detection logic, rule generator, database layer and alert import in a Linux sandbox (65 automated tests, plus a live HTTPS server and a live packet-capture run on a loopback interface). I could **not** test on Windows, with real Npcap/Suricata, PostgreSQL, a USB adapter or your router. Expect to send me errors from the first run.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Header says "Suricata: not running" | Start `start_suricata.ps1` as Administrator. Check `EVE_JSON_PATH` in `.env`. The file must be changing (Suricata writes `stats` lines regularly). |
| Suricata "Permission denied" on eve.json | Run it as Administrator. |
| "Sensor: not running" | Run `start_sensor.ps1` as Administrator and read its window. |
| Sensor says it cannot capture | Npcap not installed/running (`sc query npcap`), not Administrator, or the wrong adapter chosen. `python tools\list_interfaces.py` lists adapters. |
| Traffic chart empty, device list empty | Wrong adapter. Pick the USB adapter facing the switch in Settings. If still nothing, try the "Network Bridge" adapter and tell me what happens. |
| No alerts from tests | Attacker and victim on the same switch (see "What it can and cannot see"); rules file not in `rule-files`; Suricata not restarted after saving settings. |
| `pip install` fails | Python 3.15 is very new: install Python 3.13 and recreate `.venv` (step 4.3). |
| `setup.ps1` cannot log in to PostgreSQL | Wrong `postgres` password, or the PostgreSQL service is stopped (`services.msc`). |
| Locked out | Wait 15 minutes, or run `manage.py reset-admin`. Forgot password: use a recovery code on the login page.
| Email reset link says "not set up" | Fill in `PUBLIC_URL` and the `SMTP_*` lines in `.env`, restart `start_all.ps1`. Needs internet. | |

## Project layout

```
app/        Flask app (auth, views, API, templates, static, services)
sensor/     detectors.py, packets.py, eve_tailer.py, runner.py
suricata/   local.rules (generated)
tools/      make_cert.py, list_interfaces.py, print_config.py, targets/
tests/      pytest suite (python -m pip install -r requirements-dev.txt; python -m pytest)
setup.ps1, start_all.ps1, start_web.ps1, start_sensor.ps1, start_suricata.ps1
run_web.py, run_sensor.py, manage.py, .env (created by setup)
```

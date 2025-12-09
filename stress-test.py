import subprocess
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = "1080"
TARGET_URL = "http://127.0.0.1:9090/"
N_THREADS = 50
ROUNDS = 20

def do_request():
    try:
        subprocess.run(
            ["curl", "--socks5", f"{SOCKS_HOST}:{SOCKS_PORT}", TARGET_URL, "-s", "-o", "/dev/null"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3
        )
    except subprocess.TimeoutExpired:
        pass

def count_fds(pid):
    try:
        # macOS / Linux compatible if lsof installed
        out = subprocess.check_output(["lsof", "-p", str(pid)], stderr=subprocess.DEVNULL)
        return len(out.splitlines()) - 1
    except Exception:
        return -1

def main():
    pid = int(sys.argv[1])
    print(f"Monitoreando proceso PID={pid}")

    for round in range(ROUNDS):
        print(f"--- Ronda {round+1}/{ROUNDS} ---")

        with ThreadPoolExecutor(max_workers=N_THREADS) as executor:
            futures = [executor.submit(do_request) for _ in range(N_THREADS)]
            for f in as_completed(futures):
                pass

        time.sleep(0.2)

        fd_count = count_fds(pid)
        print(f"FDs abiertos: {fd_count}")

        # Para debugging, mostrar límite soft
        if round == 0:
            try:
                soft, hard = subprocess.check_output(["ulimit", "-n"], shell=True).decode().strip(), "?"
                print(f"Límite de archivos: soft={soft}")
            except:
                pass

        time.sleep(0.1)

    print("Test finalizado.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 stress_test.py <PID_DEL_SERVIDOR>")
        sys.exit(1)
    main()


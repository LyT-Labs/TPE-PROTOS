import subprocess
import multiprocessing
import time
import sys
from collections import Counter

# Configuración
PROXY_HOST = "127.0.0.1"
PROXY_PORT = "1080"
TARGET_URL = "http://127.0.0.1:9090/"
CONCURRENCY = 500
REQUESTS_PER_WORKER = 1
CONNECT_TIMEOUT = 5
MAX_TIME = 10

def run_worker(worker_id):
    """Ejecuta requests y retorna lista de resultados"""
    results = []
    
    for i in range(1, REQUESTS_PER_WORKER + 1):
        cmd = [
            'curl',
            '--socks5', f'{PROXY_HOST}:{PROXY_PORT}',
            '--max-time', str(MAX_TIME),
            '--connect-timeout', str(CONNECT_TIMEOUT),
            '-o', '/dev/null',
            '-s',
            '-w', '%{http_code}|%{time_total}|%{time_connect}',
            TARGET_URL
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TIME + 5)
            if result.stdout:
                parts = result.stdout.strip().split('|')
                if len(parts) == 3:
                    results.append({
                        'code': int(parts[0]) if parts[0].isdigit() else 0,
                        'time_total': float(parts[1]),
                        'time_connect': float(parts[2])
                    })
        except:
            results.append({'code': 0, 'time_total': 0.0, 'time_connect': 0.0})
    
    return results

def main():
    total_requests = CONCURRENCY * REQUESTS_PER_WORKER
    print(f"Lanzando {CONCURRENCY} workers x {REQUESTS_PER_WORKER} requests (total={total_requests})")
    print()
    
    start = time.time()
    
    with multiprocessing.Pool(processes=CONCURRENCY) as pool:
        all_results = pool.map(run_worker, range(1, CONCURRENCY + 1))
    
    elapsed = time.time() - start
    
    results = [r for worker_results in all_results for r in worker_results]
    
    # Calcular estadísticas
    codes = Counter(r['code'] for r in results)
    times = sorted([r['time_total'] for r in results if r['time_total'] > 0])
    success = sum(1 for r in results if 200 <= r['code'] < 400)
    
    print(f"Completado en {elapsed:.2f}s")
    print()
    print(f"Total:    {len(results)}")
    print(f"Exitosos: {success} ({success/len(results)*100:.1f}%)")
    print(f"Fallidos: {len(results) - success}")
    print()
    
    print("Códigos HTTP:")
    for code, count in sorted(codes.items()):
        print(f"  {code}: {count}")
    
    if times:
        print()
        print("Latencias:")
        print(f"  Min:    {min(times)*1000:.1f} ms")
        print(f"  Max:    {max(times)*1000:.1f} ms")
        print(f"  Media:  {sum(times)/len(times)*1000:.1f} ms")
        print(f"  P95:    {times[int(len(times)*0.95)]*1000:.1f} ms")

if __name__ == '__main__':
    main()

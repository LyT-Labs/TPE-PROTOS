#!/usr/bin/env python3
"""
Script simple para probar el servidor SOCKS5 usando curl.
Levanta un servidor HTTP y ejecuta múltiples curl concurrentes a través del proxy SOCKS5.
"""

import subprocess
import threading
import time
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Configuración
HTTP_SERVER_PORT = 9090
SOCKS5_PROXY = "socks5://127.0.0.1:1080"
NUM_REQUESTS = 1000

class QuietHTTPHandler(SimpleHTTPRequestHandler):
    """Handler HTTP que no imprime logs"""
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        """Responde con un mensaje simple"""
        response = b"Hello from SOCKS5 test server!"
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

def start_http_server():
    """Inicia el servidor HTTP de prueba"""
    server = HTTPServer(('127.0.0.1', HTTP_SERVER_PORT), QuietHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def run_curl_test(test_id, results):
    """Ejecuta una petición curl a través del proxy SOCKS5"""
    try:
        cmd = [
            'curl',
            '--socks5', '127.0.0.1:1080',
            '--connect-timeout', '5',
            '--max-time', '10',
            '-s',  # silent
            f'http://127.0.0.1:{HTTP_SERVER_PORT}/'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0 and "Hello from SOCKS5 test server!" in result.stdout:
            results['success'] += 1
            return True
        else:
            results['failed'] += 1
            if result.stderr:
                print(f"\nError en request {test_id}: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        results['timeout'] += 1
        print(f"\nTimeout en request {test_id}")
        return False
    except Exception as e:
        results['error'] += 1
        print(f"\nExcepción en request {test_id}: {e}")
        return False

def main():
    print("=" * 70)
    print("TEST SIMPLE SOCKS5 CON CURL")
    print("=" * 70)
    print()
    
    # Verificar que curl está instalado
    try:
        subprocess.run(['curl', '--version'], capture_output=True, check=True)
    except:
        print("✗ ERROR: curl no está instalado o no está en el PATH")
        sys.exit(1)
    
    print("✓ curl está disponible")
    
    # Iniciar servidor HTTP
    print(f"✓ Iniciando servidor HTTP en puerto {HTTP_SERVER_PORT}...")
    server = start_http_server()
    time.sleep(0.5)
    
    print(f"✓ Servidor HTTP iniciado")
    print()
    print(f"Ejecutando {NUM_REQUESTS} peticiones concurrentes a través de SOCKS5...")
    print()
    
    results = {
        'success': 0,
        'failed': 0,
        'timeout': 0,
        'error': 0
    }
    
    start_time = time.time()
    
    # Ejecutar peticiones concurrentes
    threads = []
    for i in range(NUM_REQUESTS):
        thread = threading.Thread(target=run_curl_test, args=(i, results))
        thread.start()
        threads.append(thread)
        
        # Pequeña pausa para no saturar
        if i % 50 == 0 and i > 0:
            time.sleep(0.1)
    
    # Esperar a que terminen
    for i, thread in enumerate(threads):
        thread.join()
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{NUM_REQUESTS} completados...", end='\r')
    
    elapsed = time.time() - start_time
    
    print()
    print()
    print("=" * 70)
    print("RESULTADOS")
    print("=" * 70)
    print(f"Tiempo total:      {elapsed:.2f} segundos")
    print(f"Exitosas:          {results['success']}/{NUM_REQUESTS} ({results['success']/NUM_REQUESTS*100:.1f}%)")
    print(f"Fallidas:          {results['failed']}")
    print(f"Timeouts:          {results['timeout']}")
    print(f"Errores:           {results['error']}")
    print(f"Throughput:        {NUM_REQUESTS/elapsed:.1f} req/s")
    print()
    
    # Detener servidor
    server.shutdown()
    
    if results['success'] == NUM_REQUESTS:
        print("✓ ¡TODOS LOS TESTS PASARON!")
        sys.exit(0)
    elif results['success'] >= NUM_REQUESTS * 0.9:
        print("⚠ La mayoría de los tests pasaron")
        sys.exit(0)
    else:
        print("✗ MUCHOS TESTS FALLARON")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrumpido.")
        sys.exit(1)


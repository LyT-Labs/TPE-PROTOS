# TPE-PROTOS - Servidor Proxy SOCKS5

**ITBA Protocolos de Comunicación 2025/1 - Grupo 13**

Implementación de un servidor proxy SOCKS5 según RFC 1928.

## Estructura del Proyecto

```
TPE-PROTOS/
├── docs/                         # Documentación del proyecto
├── src/                          # Código fuente
│   ├── args/                     # Parsing de argumentos CLI
│   ├── auth/                     # Autenticación SOCKS5
│   ├── connect/                  # Lógica de conexión al servidor origen
│   ├── echo_server/              # Servidor principal
│   ├── hello/                    # Handshake inicial SOCKS5
│   ├── helpers/                  # Utilidades (buffer, parser, selector, STM, metrics)
│   ├── request/                  # Procesamiento de requests SOCKS5
│   ├── resolver/                 # Resolución DNS asíncrona
│   ├── socks5/                   # Núcleo del protocolo SOCKS5
│   └── tunnel/                   # Túnel de datos bidireccional
├── build/                        # Archivos objeto (.o) - generado
├── bin/                          # Ejecutables compilados - generado
├── Makefile                      # Sistema de compilación
├── concurrent-test.py            # Script de pruebas de carga
└── README.md                     # Este archivo
```

## Compilación

```bash
make
```

Esto genera el ejecutable en `bin/echo_server` y los archivos objeto en `build/`.

Para limpiar:
```bash
make clean
```

## Artefactos Generados

- **`build/`**: Archivos objeto (.o)
- **`bin/echo_server`**: Ejecutable del servidor

## Ejecución

### Básico
```bash
./bin/echo_server
```

### Con opciones
```bash
./bin/echo_server -p 8080 -u admin:password
```

## Opciones de Línea de Comandos

```
  -h                    Imprime la ayuda
  -l <SOCKS addr>       Dirección del proxy SOCKS (default: 0.0.0.0)
  -p <SOCKS port>       Puerto SOCKS (default: 1080)
  -L <conf addr>        Dirección del servicio de management (default: 127.0.0.1)
  -P <conf port>        Puerto de configuración (default: 8080)
  -u <name>:<pass>      Usuario y contraseña (hasta 10)
  -v                    Versión
```

### Ejemplos

```bash
# Puerto personalizado
./bin/echo_server -p 9050

# Con autenticación
./bin/echo_server -u admin:pass123 -u user:abc

# Usando make
make run ARGS="-p 8080"
```

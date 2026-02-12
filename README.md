# TPE Protocolos de Comunicación - Servidor Proxy SOCKSv5

**ITBA - Protocolos de Comunicación 2025/2C - Grupo 13**

Implementación de un servidor proxy SOCKSv5 conforme a RFC 1928 y RFC 1929.

## Materiales de entrega

| Material | Ubicación |
|---|---|
| Informe del proyecto | [docs/Informe.pdf](docs/Informe.pdf) |
| Protocolo de monitoreo | [docs/PROTOCOLO_MONITOR.md](docs/PROTOCOLO_MONITOR.md) |
| Código fuente | `src/` |
| Scripts de prueba | `tests/` |
| Sistema de compilación | `Makefile` |

## Compilación

Requisitos: GCC con soporte C11, POSIX threads.

```bash
make
```

Genera los ejecutables en `bin/`:
- `bin/socks5_server` — Servidor proxy SOCKSv5
- `bin/monitor_client` — Cliente de monitoreo y configuración

Para limpiar archivos de compilación:
```bash
make clean
```

## Ejecución

### Servidor SOCKSv5

```bash
./bin/socks5_server [opciones]
```

Opciones:
```
  -h                    Muestra la ayuda
  -l <dirección>        Dirección de escucha del proxy (default: 0.0.0.0)
  -p <puerto>           Puerto del proxy SOCKS (default: 1080)
  -L <dirección>        Dirección del servicio de monitoreo (default: 127.0.0.1)
  -P <puerto>           Puerto de monitoreo (default: 8080)
  -u <usuario>:<clave>  Agrega un usuario (puede repetirse, hasta 10)
  -v                    Muestra la versión
```

Ejemplos:
```bash
# Iniciar con puerto por defecto
./bin/socks5_server

# Con autenticación
./bin/socks5_server -u admin:pass123 -u guest:guest

# Puerto personalizado y monitoreo abierto
./bin/socks5_server -p 9050 -L 0.0.0.0 -P 9090
```

### Cliente de monitoreo

```bash
./bin/monitor_client [opciones]
```

Opciones:
```
  (sin opciones)          Inicia interfaz interactiva (TUI)
  -h <host>               Dirección del servidor (default: 127.0.0.1)
  -p <puerto>             Puerto del servidor (default: 8080)
  -c <comando>            Ejecuta un comando directo (sin interfaz)
  -v                      Modo verbose
  -V                      Muestra la versión
  -?                      Muestra la ayuda
```

Ejemplos:
```bash
# Modo interactivo
./bin/monitor_client

# Ver métricas con netcat
nc 127.0.0.1 8080

# Agregar usuario en modo script
./bin/monitor_client -c "ADDUSER bob clave123"

# Reiniciar métricas
./bin/monitor_client -c "RESET"
```

## Protocolo de monitoreo

Protocolo de texto plano sobre TCP (puerto 8080 por defecto). Al conectarse, el servidor responde con las métricas actuales y queda a la espera de comandos.

Comandos disponibles:
- `RESET` — Reinicia las métricas a cero
- `ADDUSER <usuario> <clave>` — Agrega un usuario al sistema de autenticación

Documentación completa en [docs/PROTOCOLO_MONITOR.md](docs/PROTOCOLO_MONITOR.md).

## Sniffing de credenciales

El proxy inspecciona el tráfico y captura credenciales en tránsito para:
- **POP3** (puerto 110): Comandos `USER` y `PASS`
- **HTTP** (puertos 80/8080): Header `Authorization: Basic`

Las credenciales capturadas se registran en `credentials.log`.
Documentación completa en [docs/SNIFFING_CREDENCIALES.md](docs/SNIFFING_CREDENCIALES.md).

## Registro de acceso

Cada conexión a través del proxy se registra en `access.log` con timestamp, usuario, IP origen, destino y resultado, lo que permite a un administrador auditar los accesos.


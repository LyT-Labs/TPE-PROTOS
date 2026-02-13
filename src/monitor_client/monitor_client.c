/**
 * monitor_client.c
 * 
 * Cliente de monitoreo y configuración para el servidor SOCKS5 Proxy.
 * Permite consultar métricas y ejecutar comandos de administración.
 * 
 * ITBA Protocolos de Comunicación 2025/2C - Grupo 13
 */

#include "monitor_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

// Tamaño del buffer de recepción
#define BUFFER_SIZE 8192

/**
 * Imprime el uso del programa
 */
void print_usage(const char *progname) {
    fprintf(stderr,
            "Uso: %s [OPCIONES]\n"
            "\n"
            "Cliente de monitoreo y configuración para servidor SOCKS5.\n"
            "\n"
            "Modo por defecto: INTERACTIVO (menú de opciones)\n"
            "\n"
            "Opciones:\n"
            "  -h <host>        Dirección del servidor (default: 127.0.0.1)\n"
            "  -p <port>        Puerto del servidor (default: 8080)\n"
            "  -c <command>     Modo no interactivo: ejecutar comando directo\n"
            "  -v               Modo verbose\n"
            "  -V               Muestra la versión y termina\n"
            "  -?               Muestra esta ayuda\n"
            "\n"
            "Ejemplos:\n"
            "  %s                              # Modo interactivo (RECOMENDADO)\n"
            "  %s -h 192.168.1.10              # Interactivo en servidor remoto\n"
            "  %s -c \"RESET\"                   # Modo script: reiniciar métricas\n"
            "  %s -c \"ADDUSER alice pass123\"   # Modo script: agregar usuario\n"
            "\n",
            progname, progname, progname, progname, progname);
}

/**
 * Imprime la versión del programa
 */
void print_version(void) {
    fprintf(stderr, "monitor_client version 1.0\n"
                    "ITBA Protocolos de Comunicación 2025/2C -- Grupo 13\n");
}

/**
 * Conecta al servidor de monitoreo
 */
static int connect_to_server(const char *host, const char *port, bool verbose) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sock_fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 o IPv6
    hints.ai_socktype = SOCK_STREAM;

    if (verbose) {
        fprintf(stderr, "[DEBUG] Resolviendo %s:%s...\n", host, port);
    }

    int err = getaddrinfo(host, port, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "Error getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    // Intentar conectar con cada dirección
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd == -1) {
            continue;
        }

        if (verbose) {
            char addr_str[INET6_ADDRSTRLEN];
            void *addr_ptr;
            
            if (rp->ai_family == AF_INET) {
                addr_ptr = &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
            } else {
                addr_ptr = &((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr;
            }
            
            inet_ntop(rp->ai_family, addr_ptr, addr_str, sizeof(addr_str));
            fprintf(stderr, "[DEBUG] Intentando conectar a %s...\n", addr_str);
        }

        if (connect(sock_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            if (verbose) {
                fprintf(stderr, "[DEBUG] Conexión establecida\n");
            }
            break;  // Éxito
        }

        close(sock_fd);
        sock_fd = -1;
    }

    freeaddrinfo(result);

    if (sock_fd == -1) {
        fprintf(stderr, "Error: No se pudo conectar a %s:%s\n", host, port);
        return -1;
    }

    return sock_fd;
}

/**
 * Envía un comando al servidor
 */
static int send_command(int sock_fd, const char *command, bool verbose) {
    size_t cmd_len = strlen(command);
    
    // Asegurar que el comando termina con \n
    char *cmd_with_newline = malloc(cmd_len + 2);
    if (cmd_with_newline == NULL) {
        perror("malloc");
        return -1;
    }
    
    strcpy(cmd_with_newline, command);
    if (command[cmd_len - 1] != '\n') {
        strcat(cmd_with_newline, "\n");
        cmd_len++;
    }

    if (verbose) {
        fprintf(stderr, "[DEBUG] Enviando comando: %s", cmd_with_newline);
    }

    ssize_t sent = send(sock_fd, cmd_with_newline, cmd_len, 0);
    free(cmd_with_newline);

    if (sent == -1) {
        perror("send");
        return -1;
    }

    if ((size_t)sent != cmd_len) {
        fprintf(stderr, "Error: No se pudo enviar el comando completo\n");
        return -1;
    }

    return 0;
}

/**
 * Recibe y muestra la respuesta del servidor
 */
static int receive_response(int sock_fd, bool verbose) {
    char buffer[BUFFER_SIZE];
    ssize_t received;
    size_t total_received = 0;

    if (verbose) {
        fprintf(stderr, "[DEBUG] Esperando respuesta...\n");
    }

    while ((received = recv(sock_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[received] = '\0';
        printf("%s", buffer);
        fflush(stdout);
        
        total_received += received;

        // Si recibimos menos del buffer, probablemente terminamos
        if (received < (ssize_t)sizeof(buffer) - 1) {
            break;
        }
    }

    if (received == -1) {
        perror("recv");
        return -1;
    }

    if (verbose) {
        fprintf(stderr, "[DEBUG] Recibidos %zu bytes\n", total_received);
    }

    if (total_received == 0) {
        fprintf(stderr, "Advertencia: No se recibió respuesta del servidor\n");
    }

    return 0;
}

/**
 * Limpia la pantalla
 */
static void clear_screen(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

/**
 * Imprime el banner del cliente
 */
static void print_banner(const char *host, const char *port) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         SOCKS5 Proxy - Cliente de Monitoreo v1.0             ║\n");
    printf("║              ITBA Protocolos 2025/2C - Grupo 13              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Conectado a: %s:%s\n", host, port);
    printf("\n");
}

/**
 * Muestra el menú principal
 */
static void print_menu(void) {
    printf("──────────────────────────────────────────────────────────────\n");
    printf("                        MENÚ PRINCIPAL\n");
    printf("──────────────────────────────────────────────────────────────\n");
    printf("\n");
    printf("  1. Ver métricas del servidor\n");
    printf("  2. Agregar nuevo usuario\n");
    printf("  3. Reiniciar métricas\n");
    printf("  4. Salir\n");
    printf("\n");
    printf("──────────────────────────────────────────────────────────────\n");
    printf("\nSeleccione una opción: ");
    fflush(stdout);
}

/**
 * Lee una línea de entrada del usuario
 */
static int read_input(char *buffer, size_t size) {
    if (fgets(buffer, size, stdin) == NULL) {
        return -1;
    }
    
    // Eliminar newline
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    
    return 0;
}

/**
 * Espera que el usuario presione Enter
 */
static void wait_for_enter(void) {
    printf("\nPresione ENTER para continuar...");
    fflush(stdout);
    getchar();
}

/**
 * Ejecuta un comando y muestra la respuesta
 */
static int execute_and_show(const char *host, const char *port, const char *command, bool verbose) {
    int sock_fd = connect_to_server(host, port, verbose);
    if (sock_fd == -1) {
        printf("\n❌ Error: No se pudo conectar al servidor\n");
        return -1;
    }

    if (command != NULL && send_command(sock_fd, command, verbose) == -1) {
        printf("\n❌ Error: No se pudo enviar el comando\n");
        close(sock_fd);
        return -1;
    }

    if (receive_response(sock_fd, verbose) == -1) {
        printf("\n❌ Error: No se pudo recibir la respuesta\n");
        close(sock_fd);
        return -1;
    }

    close(sock_fd);
    return 0;
}

/**
 * Modo interactivo con menú
 */
static int interactive_mode(const struct client_config *config) {
    char input[256];
    int option;
    bool running = true;

    clear_screen();
    print_banner(config->host, config->port);

    while (running) {
        print_menu();
        
        if (read_input(input, sizeof(input)) == -1) {
            break;
        }

        option = atoi(input);
        printf("\n");

        switch (option) {
            case 1: {
                // Ver métricas
                printf("═══════════════════ MÉTRICAS DEL SERVIDOR ════════════════════\n\n");
                execute_and_show(config->host, config->port, NULL, config->verbose);
                wait_for_enter();
                clear_screen();
                print_banner(config->host, config->port);
                break;
            }

            case 2: {
                // Agregar usuario
                char username[256];
                char password[256];
                char command[512];

                printf("═══════════════════ AGREGAR NUEVO USUARIO ════════════════════\n\n");
                printf("Usuario (sin espacios): ");
                fflush(stdout);
                
                if (read_input(username, sizeof(username)) == -1 || strlen(username) == 0) {
                    printf("\n❌ Usuario inválido\n");
                    wait_for_enter();
                    clear_screen();
                    print_banner(config->host, config->port);
                    break;
                }

                printf("Contraseña (sin espacios): ");
                fflush(stdout);
                
                if (read_input(password, sizeof(password)) == -1 || strlen(password) == 0) {
                    printf("\n❌ Contraseña inválida\n");
                    wait_for_enter();
                    clear_screen();
                    print_banner(config->host, config->port);
                    break;
                }

                snprintf(command, sizeof(command), "ADDUSER %s %s", username, password);
                printf("\n");
                execute_and_show(config->host, config->port, command, config->verbose);
                wait_for_enter();
                clear_screen();
                print_banner(config->host, config->port);
                break;
            }

            case 3: {
                // Reiniciar métricas
                char confirm[10];
                printf("═══════════════════ REINICIAR MÉTRICAS ═══════════════════════\n\n");
                printf("⚠️  Esto pondrá todos los contadores en cero.\n");
                printf("¿Está seguro? (s/N): ");
                fflush(stdout);

                if (read_input(confirm, sizeof(confirm)) != -1 && 
                    (strcmp(confirm, "s") == 0 || strcmp(confirm, "S") == 0)) {
                    printf("\n");
                    execute_and_show(config->host, config->port, "RESET\n", config->verbose);
                } else {
                    printf("\n❌ Operación cancelada\n");
                }
                wait_for_enter();
                clear_screen();
                print_banner(config->host, config->port);
                break;
            }

            case 4: {
                // Salir
                printf("👋 Hasta luego!\n\n");
                running = false;
                break;
            }

            default: {
                printf("❌ Opción inválida. Por favor, seleccione 1-4.\n");
                wait_for_enter();
                clear_screen();
                print_banner(config->host, config->port);
                break;
            }
        }
    }

    return CLIENT_SUCCESS;
}

/**
 * Función principal de conexión al servidor (modo no interactivo)
 */
int monitor_client_connect(const struct client_config *config) {
    int sock_fd = -1;
    int ret = CLIENT_SUCCESS;

    // Conectar al servidor
    sock_fd = connect_to_server(config->host, config->port, config->verbose);
    if (sock_fd == -1) {
        return CLIENT_ERR_CONNECT;
    }

    // Si hay comando, enviarlo
    if (config->command != NULL) {
        if (send_command(sock_fd, config->command, config->verbose) == -1) {
            ret = CLIENT_ERR_SEND;
            goto cleanup;
        }
    }

    // Recibir respuesta
    if (receive_response(sock_fd, config->verbose) == -1) {
        ret = CLIENT_ERR_RECV;
        goto cleanup;
    }

cleanup:
    if (sock_fd != -1) {
        close(sock_fd);
        if (config->verbose) {
            fprintf(stderr, "[DEBUG] Conexión cerrada\n");
        }
    }

    return ret;
}

/**
 * Función main
 */
int main(int argc, char **argv) {
    struct client_config config = {
        .host = "127.0.0.1",
        .port = "8080",
        .command = NULL,
        .verbose = false
    };

    // Parsear argumentos
    int opt;
    while ((opt = getopt(argc, argv, "h:p:c:vV?")) != -1) {
        switch (opt) {
            case 'h':
                config.host = optarg;
                break;
            case 'p':
                config.port = optarg;
                break;
            case 'c':
                config.command = optarg;
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'V':
                print_version();
                return CLIENT_SUCCESS;
            case '?':
            default:
                print_usage(argv[0]);
                return CLIENT_ERR_ARGS;
        }
    }

    // Decidir modo de ejecución
    int ret;
    
    if (config.command != NULL) {
        // Modo no interactivo (comando directo para scripts)
        ret = monitor_client_connect(&config);

        if (ret != CLIENT_SUCCESS) {
            switch (ret) {
                case CLIENT_ERR_CONNECT:
                    fprintf(stderr, "Error: No se pudo conectar al servidor\n");
                    break;
                case CLIENT_ERR_SEND:
                    fprintf(stderr, "Error: No se pudo enviar el comando\n");
                    break;
                case CLIENT_ERR_RECV:
                    fprintf(stderr, "Error: No se pudo recibir la respuesta\n");
                    break;
            }
            return ret;
        }
    } else {
        // Modo interactivo (TUI con menú)
        ret = interactive_mode(&config);
    }

    return ret;
}

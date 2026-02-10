#include "monitor.h"
#include "metrics.h"
#include "selector.h"
#include "../auth/auth.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

static int monitor_fd = -1;

struct monitor_client {
    char buffer[8192];
    size_t len;
    size_t sent;
    bool received_command;
    
    // Buffer acumulativo para comandos recibidos
    char recv_buffer[1024];
    size_t recv_len;
};

static void monitor_accept(struct selector_key *key);
static void monitor_client_read(struct selector_key *key);
static void monitor_client_write(struct selector_key *key);
static void monitor_client_close(struct selector_key *key);

static const struct fd_handler monitor_handler = {
    .handle_read  = monitor_accept,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = NULL,
};

static const struct fd_handler monitor_client_handler = {
    .handle_read  = monitor_client_read,
    .handle_write = monitor_client_write,
    .handle_block = NULL,
    .handle_close = monitor_client_close,
};

const struct fd_handler * monitor_get_handler(void) {
    return &monitor_handler;
}

int monitor_init(fd_selector s, const char *addr, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int listen_fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 o IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // Para bind

    int err = getaddrinfo(addr, port, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "monitor getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(listen_fd);
        listen_fd = -1;
    }

    freeaddrinfo(result);

    if (listen_fd == -1) {
        fprintf(stderr, "monitor: no se pudo hacer bind\n");
        return -1;
    }

    if (listen(listen_fd, 5) == -1) {
        perror("monitor listen");
        close(listen_fd);
        return -1;
    }

    int flags = fcntl(listen_fd, F_GETFL, 0);
    if (flags == -1 || fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("monitor fcntl O_NONBLOCK");
        close(listen_fd);
        return -1;
    }

    selector_status st = selector_register(s, listen_fd, &monitor_handler, OP_READ, NULL);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "monitor: selector_register falló: %s\n", selector_error(st));
        close(listen_fd);
        return -1;
    }

    monitor_fd = listen_fd;
    return 0;
}

static void monitor_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("monitor accept");
        }
        return;
    }

    if (selector_fd_set_nio(client_fd) == -1) {
        perror("monitor: selector_fd_set_nio");
        close(client_fd);
        return;
    }

    struct monitor_client *mc = malloc(sizeof(*mc));
    if (mc == NULL) {
        perror("monitor: malloc monitor_client");
        close(client_fd);
        return;
    }

    memset(mc, 0, sizeof(*mc));

    struct socks5_metrics *m = metrics_get();

    int offset = 0;

    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "=== SOCKS5 Server Metrics ===\n\n");

    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "Connections:\n");
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  total_connections:         %llu\n", 
                      (unsigned long long)m->total_connections);
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  current_connections:       %llu\n",
                      (unsigned long long)m->current_connections);
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  max_concurrent_connections: %llu\n\n",
                      (unsigned long long)m->max_concurrent_connections);

    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "Data Transfer:\n");
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  bytes_client_to_origin: %llu\n",
                      (unsigned long long)m->bytes_client_to_origin);
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  bytes_origin_to_client: %llu\n\n",
                      (unsigned long long)m->bytes_origin_to_client);

    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "Authentication:\n");
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  auth_ok:                %llu\n",
                      (unsigned long long)m->auth_ok);
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  auth_fail:              %llu\n\n",
                      (unsigned long long)m->auth_fail);

    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "DNS Resolution:\n");
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  dns_ok:                 %llu\n",
                      (unsigned long long)m->dns_ok);
    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "  dns_fail:               %llu\n\n",
                      (unsigned long long)m->dns_fail);

    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                      "Reply Codes:\n");

    for (int i = 0; i < 256; i++) {
        if (m->rep_code_count[i] > 0) {
            offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset,
                              "  rep[0x%02X]:              %llu\n",
                              i, (unsigned long long)m->rep_code_count[i]);
        }
    }

    offset += snprintf(mc->buffer + offset, sizeof(mc->buffer) - offset, "\n");

    mc->len = offset;
    mc->sent = 0;
    mc->received_command = false;

    selector_status st = selector_register(key->s, client_fd, &monitor_client_handler, OP_READ | OP_WRITE, mc);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "monitor: selector_register client falló: %s\n", selector_error(st));
        close(client_fd);
        free(mc);
        return;
    }
}

static void monitor_client_read(struct selector_key *key) {
    struct monitor_client *mc = key->data;
    if (mc == NULL) {
        return;
    }

    // Leer datos en el buffer acumulativo
    ssize_t n = recv(key->fd, mc->recv_buffer + mc->recv_len, 
                     sizeof(mc->recv_buffer) - mc->recv_len - 1, 0);

    if (n > 0) {
        mc->recv_len += n;
        mc->recv_buffer[mc->recv_len] = '\0';
        
        // Buscar línea completa (terminada en \n o \r\n)
        char *newline = strchr(mc->recv_buffer, '\n');
        if (newline == NULL) {
            // No hay línea completa aún
            if (mc->recv_len >= sizeof(mc->recv_buffer) - 1) {
                // Buffer lleno sin newline = comando demasiado largo
                const char *response = "ERROR: command too long\n";
                size_t resp_len = strlen(response);
                if (resp_len < sizeof(mc->buffer)) {
                    memcpy(mc->buffer, response, resp_len);
                    mc->len = resp_len;
                    mc->sent = 0;
                    mc->recv_len = 0;
                    selector_set_interest(key->s, key->fd, OP_WRITE);
                }
            }
            // Esperar más datos
            return;
        }

        // Tenemos línea completa, procesarla
        mc->received_command = true;
        *newline = '\0';
        
        // Eliminar \r si existe
        char *end = mc->recv_buffer + strlen(mc->recv_buffer) - 1;
        while (end >= mc->recv_buffer && (*end == '\r' || *end == '\n')) {
            *end = '\0';
            end--;
        }

        mc->len = 0;
        mc->sent = 0;

        // Parsear comando
        char *tokens[3] = {NULL, NULL, NULL};
        int token_count = 0;
        char *saveptr = NULL;
        char *token = strtok_r(mc->recv_buffer, " ", &saveptr);
        
        while (token != NULL && token_count < 3) {
            tokens[token_count++] = token;
            token = strtok_r(NULL, " ", &saveptr);
        }

        if (token_count == 1 && strcmp(tokens[0], "RESET") == 0) {
            metrics_reset();

            const char *response = "OK: metrics reset\n";
            size_t resp_len = strlen(response);
            
            if (resp_len < sizeof(mc->buffer)) {
                memcpy(mc->buffer, response, resp_len);
                mc->len = resp_len;
            }
        } else if (token_count == 3 && strcmp(tokens[0], "ADDUSER") == 0) {
            const char *username = tokens[1];
            const char *password = tokens[2];

            bool result = auth_add_user(username, password);
            
            const char *response;
            if (result) {
                response = "OK: user added\n";
            } else {
                bool has_content = false;
                for (const char *p = username; *p != '\0'; p++) {
                    if (!isspace((unsigned char)*p)) {
                        has_content = true;
                        break;
                    }
                }
                
                if (!has_content) {
                    response = "ERROR: invalid username\n";
                } else {
                    response = "ERROR: user exists or table full\n";
                }
            }
            
            size_t resp_len = strlen(response);
            if (resp_len < sizeof(mc->buffer)) {
                memcpy(mc->buffer, response, resp_len);
                mc->len = resp_len;
            }
        } else {
            const char *response = "ERROR: unknown command\n";
            size_t resp_len = strlen(response);
            
            if (resp_len < sizeof(mc->buffer)) {
                memcpy(mc->buffer, response, resp_len);
                mc->len = resp_len;
            }
        }

        // Reset recv_buffer para próximo comando
        mc->recv_len = 0;
        
        selector_set_interest(key->s, key->fd, OP_WRITE);

    } else if (n == 0) {
        selector_unregister_fd(key->s, key->fd);
        close(key->fd);
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            selector_unregister_fd(key->s, key->fd);
            close(key->fd);
        }
    }
}

static void monitor_client_write(struct selector_key *key) {
    struct monitor_client *mc = key->data;
    if (mc == NULL) {
        return;
    }
    ssize_t n = send(key->fd, mc->buffer + mc->sent, mc->len - mc->sent, 0);

    if (n > 0) {
        mc->sent += n;

        if (mc->sent == mc->len) {
            selector_unregister_fd(key->s, key->fd);
            close(key->fd);
        }
    } else if (n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        selector_unregister_fd(key->s, key->fd);
        close(key->fd);
    }
}

static void monitor_client_close(struct selector_key *key) {
    struct monitor_client *mc = key->data;
    if (mc != NULL) {
        free(mc);
        key->data = NULL;
    }
}

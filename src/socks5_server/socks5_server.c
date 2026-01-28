#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "socks5_server.h"
#include "../helpers/monitor.h"
#include "../resolver/resolver.h"
#include "../args/args.h"
#include "../auth/auth.h"

#define SOCKS5_DEFAULT_PORT 1080
#define SOCKS5_BUFFER_SIZE  4096

// Variable global para señal de terminación
static volatile sig_atomic_t server_should_stop = 0;
static fd_selector global_selector = NULL;

struct echo_conn {
    int     fd;
    buffer  read_buf;
    buffer  write_buf;
    uint8_t read_raw[SOCKS5_BUFFER_SIZE];
    uint8_t write_raw[SOCKS5_BUFFER_SIZE];
};

static void accept_handler(struct selector_key *key);
static void echo_read    (struct selector_key *key);
static void echo_write   (struct selector_key *key);
static void echo_close   (struct selector_key *key);

static const struct fd_handler acceptor_handler = {
    .handle_read   = accept_handler,
    .handle_write  = NULL,
    .handle_block  = NULL,
    .handle_close  = NULL,
};

static const struct fd_handler echo_handler = {
    .handle_read   = echo_read,
    .handle_write  = echo_write,
    .handle_block  = NULL,
    .handle_close  = echo_close,
};

static void fatal_connection_error(struct selector_key *key, const char *msg) {
    fprintf(stderr, "%s on fd %d: %s\n", msg, key->fd, strerror(errno));
    selector_unregister_fd(key->s, key->fd);
}

static void accept_handler(struct selector_key *key) {
    int server_fd = key->fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return;
    }

    if (selector_fd_set_nio(client_fd) == -1) {
        perror("selector_fd_set_nio (client)");
        close(client_fd);
        return;
    }

    // ESTO ES DEL ECHO-SERVER
    // struct echo_conn *conn = malloc(sizeof(*conn));
    // if (conn == NULL) {
    //     perror("malloc echo_conn");
    //     close(client_fd);
    //     return;
    // }

    // conn->fd = client_fd;

    // buffer_init(&conn->read_buf,  sizeof(conn->read_raw),  conn->read_raw);
    // buffer_init(&conn->write_buf, sizeof(conn->write_raw), conn->write_raw);

    // char client_ip[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

    // printf("Nueva conexión desde %s:%d en fd %d\n",
    //        client_ip, ntohs(client_addr.sin_port), client_fd);

    // selector_status st = selector_register(key->s, client_fd, &echo_handler, OP_READ, conn);
    // if (st != SELECTOR_SUCCESS) {
    //     fprintf(stderr, "selector_register failed: %s\n",
    //             selector_error(st));
    //     close(client_fd);
    //     free(conn);
    //     return;
    // }

    // ESTO ES PARA PROBAR LA STM
    struct socks5_conn *conn = socks5_new(client_fd);
    if (conn == NULL) {
        perror("socks5_new");
        close(client_fd);
        return;
    }

    const struct fd_handler *h = socks5_get_handler();

    selector_status st = selector_register(key->s, client_fd, h, OP_READ, conn);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register failed: %s\n",
                selector_error(st));
        socks5_destroy(conn);
        close(client_fd);
        return;
    }

}

static void echo_read(struct selector_key *key) {
    struct echo_conn *conn = (struct echo_conn *)key->data;
    buffer *write_b = &conn->write_buf;

    size_t space;
    uint8_t *w = buffer_write_ptr(write_b, &space);

    if (space == 0) {
        fprintf(stderr, "echo_read: write buffer full on fd %d\n", key->fd);
        return;
    }

    ssize_t n = recv(key->fd, w, space, 0);
    if (n == 0) {
        printf("Cliente cerró la conexión en fd %d\n", key->fd);
        selector_unregister_fd(key->s, key->fd);
        return;
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        fatal_connection_error(key, "recv");
        return;
    }

    buffer_write_adv(write_b, n);
    selector_set_interest_key(key, OP_WRITE);
}

static void echo_write(struct selector_key *key) {
    struct echo_conn *conn = (struct echo_conn *)key->data;
    buffer *write_b = &conn->write_buf;

    if (!buffer_can_read(write_b)) {
        selector_set_interest_key(key, OP_READ);
        return;
    }

    size_t nbytes;
    uint8_t *r = buffer_read_ptr(write_b, &nbytes);

    ssize_t n = send(key->fd, r, nbytes, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        fatal_connection_error(key, "send");
        return;
    }

    buffer_read_adv(write_b, n);

    if (!buffer_can_read(write_b)) {
        selector_set_interest_key(key, OP_READ);
    } else {
        selector_set_interest_key(key, OP_WRITE);
    }
}

static void echo_close(struct selector_key *key) {
    struct echo_conn *conn = (struct echo_conn *)key->data;

    printf("Cerrando fd %d\n", key->fd);

    if (conn != NULL) {
        free(conn);
    }

    close(key->fd);
}

// Handler para señales de terminación
static void signal_handler(int sig) {
    (void)sig;  // Evitar warning de parámetro no usado
    server_should_stop = 1;
    // pselect retornará con EINTR, el loop verificará server_should_stop
}

// Configura los handlers de señales
static int setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction SIGINT");
        return -1;
    }

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction SIGTERM");
        return -1;
    }

    // Ignorar SIGPIPE (conexiones cerradas inesperadamente)
    signal(SIGPIPE, SIG_IGN);

    return 0;
}

int socks5_server_main(int argc, char *argv[]) {
    struct socks5args args;
    parse_args(argc, argv, &args);

    auth_set_users(args.users, MAX_USERS);

    // Configurar manejadores de señales
    if (setup_signal_handlers() == -1) {
        fprintf(stderr, "Error: no se pudieron configurar los manejadores de señales\n");
        return 1;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    selector_status st = selector_init(&conf);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_init: %s\n", selector_error(st));
        return EXIT_FAILURE;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        selector_close();
        return EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", args.socks_port);

    int gai_err = getaddrinfo(args.socks_addr, port_str, &hints, &res);
    if (gai_err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_err));
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

    if (bind(server_fd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        freeaddrinfo(res);
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

    freeaddrinfo(res);

    if (listen(server_fd, 20) == -1) {
        perror("listen");
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

    if (selector_fd_set_nio(server_fd) == -1) {
        perror("selector_fd_set_nio (server)");
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

    fd_selector sel = selector_new(1024);
    if (sel == NULL) {
        fprintf(stderr, "selector_new: sin memoria\n");
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

    st = selector_register(sel, server_fd, &acceptor_handler, OP_READ, NULL);
    if (st != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register (server): %s\n", selector_error(st));
        selector_destroy(sel);
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

    printf("SOCKS5 proxy escuchando en %s:%u\n", args.socks_addr, args.socks_port);

    // Inicializar el subsistema de resolución DNS asíncrona
    if (!resolver_init(2)) {
        fprintf(stderr, "Advertencia: no se pudo inicializar el resolver asíncrono\n");
        fprintf(stderr, "Las resoluciones DNS podrían fallar.\n");
    } else {
        if (!resolver_register_notification_fd(sel)) {
            fprintf(stderr, "Advertencia: no se pudo registrar el resolver en el selector\n");
            resolver_destroy();
        } else {
            printf("Resolver DNS asíncrono inicializado (2 threads)\n");
        }
    }

    char mng_port_str[16];
    snprintf(mng_port_str, sizeof(mng_port_str), "%u", args.mng_port);
    
    if (monitor_init(sel, args.mng_addr, mng_port_str) == -1) {
        fprintf(stderr, "Advertencia: no se pudo inicializar el monitor en %s:%u\n", 
                args.mng_addr, args.mng_port);
        fprintf(stderr, "El servidor continuará sin monitoreo.\n");
    } else {
        printf("Monitor de métricas escuchando en %s:%u\n", args.mng_addr, args.mng_port);
    }

    printf("Servidor SOCKS5 escuchando. Presione Ctrl-C para detener.\n");

    while (!server_should_stop) {
        st = selector_select(sel);
        if (st != SELECTOR_SUCCESS) {
            if (!server_should_stop) {
                fprintf(stderr, "selector_select: %s\n", selector_error(st));
            }
            break;
        }
    }

    printf("\nCerrando servidor...\n");

    // Limpieza ordenada
    global_selector = NULL;
    resolver_destroy();
    selector_destroy(sel);
    selector_close();
    close(server_fd);

    printf("Servidor cerrado correctamente.\n");

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    return socks5_server_main(argc, argv);
}

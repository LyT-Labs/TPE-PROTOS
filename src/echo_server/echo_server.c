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

#include "echo_server.h"

#define ECHO_DEFAULT_PORT 1080
#define ECHO_BUFFER_SIZE  4096

struct echo_conn {
    int     fd;
    buffer  read_buf;
    buffer  write_buf;
    uint8_t read_raw[ECHO_BUFFER_SIZE];
    uint8_t write_raw[ECHO_BUFFER_SIZE];
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

int echo_server_main(int argc, char *argv[]) {
    uint16_t port = ECHO_DEFAULT_PORT;

    if (argc == 2) {
        int p = atoi(argv[1]);
        if (p > 0 && p < 65536) {
            port = (uint16_t)p;
        } else {
            fprintf(stderr, "Puerto inválido '%s', usando %d\n", argv[1], port);
        }
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

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(server_fd);
        selector_close();
        return EXIT_FAILURE;
    }

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

    printf("Echo-server no bloqueante escuchando en puerto %d\n", port);

    while (1) {
        st = selector_select(sel);
        if (st != SELECTOR_SUCCESS) {
            fprintf(stderr, "selector_select: %s\n", selector_error(st));
            break;
        }
    }

    selector_destroy(sel);
    selector_close();
    close(server_fd);

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    return echo_server_main(argc, argv);
}

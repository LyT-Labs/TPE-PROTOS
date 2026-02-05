#include "connect.h"
#include "../socks5/socks5.h"
#include "../tunnel/tunnel.h"
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

// ============================================================================
// ESTADOS DE CONEXION AL ORIGIN
// ============================================================================

static int connect_set_non_blocking(int fd) {
    const int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void origin_connect_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    selector_set_interest_key(key, OP_WRITE);
}

unsigned origin_connect_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    int err = 0;
    socklen_t len = sizeof(err);

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        // getsockopt falló — liberar addrinfo y reportar error
        if (conn->addrinfo_list != NULL) {
            freeaddrinfo(conn->addrinfo_list);
            conn->addrinfo_list = NULL;
            conn->addrinfo_current = NULL;
        }
        return O_ERROR;
    }

    if (err != 0) {
        // ================================================================
        // Conexión falló — intentar siguiente dirección si hay disponibles
        // ================================================================
        if (conn->addrinfo_current != NULL) {
            // Desregistrar y cerrar el fd actual
            selector_unregister_fd(key->s, key->fd);
            close(key->fd);
            conn->origin_fd = -1;

            struct addrinfo *rp;
            int new_fd = -1;
            bool immediate = false;

            for (rp = conn->addrinfo_current; rp != NULL; rp = rp->ai_next) {
                new_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (new_fd == -1) continue;

                if (connect_set_non_blocking(new_fd) == -1) {
                    close(new_fd);
                    new_fd = -1;
                    continue;
                }

                int cr = connect(new_fd, rp->ai_addr, rp->ai_addrlen);
                if (cr == 0) {
                    memcpy(&conn->origin_addr, rp->ai_addr, rp->ai_addrlen);
                    conn->origin_addr_len = rp->ai_addrlen;
                    immediate = true;
                    conn->addrinfo_current = rp->ai_next;
                    break;
                }
                if (cr == -1 && errno == EINPROGRESS) {
                    memcpy(&conn->origin_addr, rp->ai_addr, rp->ai_addrlen);
                    conn->origin_addr_len = rp->ai_addrlen;
                    immediate = false;
                    conn->addrinfo_current = rp->ai_next;
                    break;
                }

                close(new_fd);
                new_fd = -1;
            }

            if (new_fd != -1) {
                conn->origin_fd = new_fd;

                if (immediate) {
                    // Conexión inmediata exitosa
                    freeaddrinfo(conn->addrinfo_list);
                    conn->addrinfo_list = NULL;
                    conn->addrinfo_current = NULL;

                    if (selector_register(key->s, new_fd, socks5_get_handler(),
                                          OP_WRITE, conn) != SELECTOR_SUCCESS) {
                        close(new_fd);
                        conn->origin_fd = -1;
                        uint8_t addr[4] = {0, 0, 0, 0};
                        client_set_reply(conn, 0x01, 0x01, addr, 0);
                        conn->reply_ready = true;
                        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
                        return O_CONNECTING;
                    }
                    conn->reply_code = 0x00;
                    prepare_bound_addr(conn);
                    conn->reply_ready = true;
                    selector_set_interest(key->s, conn->client_fd, OP_WRITE);
                    selector_set_interest(key->s, new_fd, OP_NOOP);
                    return O_CONNECTING;
                }

                // EINPROGRESS — esperar que el nuevo fd se conecte
                if (selector_register(key->s, new_fd, socks5_get_handler(),
                                      OP_WRITE, conn) != SELECTOR_SUCCESS) {
                    close(new_fd);
                    conn->origin_fd = -1;
                    freeaddrinfo(conn->addrinfo_list);
                    conn->addrinfo_list = NULL;
                    conn->addrinfo_current = NULL;
                    uint8_t addr[4] = {0, 0, 0, 0};
                    client_set_reply(conn, 0x05, 0x01, addr, 0);
                    conn->reply_ready = true;
                    selector_set_interest(key->s, conn->client_fd, OP_WRITE);
                    return O_CONNECTING;
                }
                // Quedarse en O_CONNECT — el nuevo fd disparará write-ready
                return O_CONNECT;
            }

            // Todas las direcciones agotadas
            freeaddrinfo(conn->addrinfo_list);
            conn->addrinfo_list = NULL;
            conn->addrinfo_current = NULL;
        }

        // No hay más direcciones — reportar error al cliente
        uint8_t addr[4] = {0, 0, 0, 0};
        client_set_reply(conn, 0x05, 0x01, addr, 0);
        conn->reply_ready = true;
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        // Si el fd ya fue desregistrado (retry path), no usar key->fd
        if (conn->origin_fd != -1) {
            selector_set_interest_key(key, OP_NOOP);
        }
        return O_CONNECTING;
    }

    // ================================================================
    // Conexión exitosa — liberar addrinfo si quedaba pendiente
    // ================================================================
    if (conn->addrinfo_list != NULL) {
        freeaddrinfo(conn->addrinfo_list);
        conn->addrinfo_list = NULL;
        conn->addrinfo_current = NULL;
    }

    conn->reply_code = 0x00;
    prepare_bound_addr(conn);
    conn->reply_ready = true;
    selector_set_interest(key->s, conn->client_fd, OP_WRITE);
    selector_set_interest_key(key, OP_NOOP);
    return O_CONNECTING;
}

void origin_connecting_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    selector_set_interest_key(key, OP_NOOP);
}

unsigned origin_connecting_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (!conn->reply_sent) {
        return O_CONNECTING;
    }
    if (conn->reply_code != 0x00) {
        return O_DONE;
    }
    return O_TUNNEL;
}

unsigned origin_connecting_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (!conn->reply_sent) {
        return O_CONNECTING;
    }
    if (conn->reply_code != 0x00) {
        return O_DONE;
    }
    return O_TUNNEL;
}

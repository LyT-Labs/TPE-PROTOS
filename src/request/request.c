#define _POSIX_C_SOURCE 200809L
#include "request.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include "../socks5/socks5.h"
#include "../tunnel/tunnel.h"

// ============================================================================  
// Tabla de transiciones del parser (por ahora vacía)
// ============================================================================

static const struct parser_state_transition *request_states[] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static const size_t request_states_n[] = {
    0,0,0,0,0,0,0,0
};

static const struct parser_definition request_parser_def = {
    .states_count = 8,
    .states = request_states,
    .states_n = request_states_n,
    .start_state = REQUEST_VERSION,
};

// ============================================================================  
// Implementación pública — todas las funciones vacías por ahora
// ============================================================================

void request_parser_init(struct request_parser *p) {
    p->parser = parser_init(parser_no_classes(), &request_parser_def);
    p->state = REQUEST_VERSION;
    p->ver = 0;
    p->cmd = 0;
    p->atyp = 0;
    p->addr_len = 0;
    p->expected_len = 0;
    p->has_addr_len = false;
    p->port_len = 0;
    p->port = 0;
}

enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored) {
    if (errored != NULL) {
        *errored = false;
    }

    while (buffer_can_read(b)) {
        size_t count;
        const uint8_t *ptr = buffer_read_ptr(b, &count);
        
        if (count == 0) {
            break;
        }

        const uint8_t c = ptr[0];
        buffer_read_adv(b, 1);

        switch (p->state) {
            case REQUEST_VERSION:
                p->ver = c;
                if (c != 0x05) {
                    p->state = REQUEST_ERROR;
                    if (errored != NULL) {
                        *errored = true;
                    }
                    return p->state;
                }
                p->state = REQUEST_CMD;
                break;

            case REQUEST_CMD:
                p->cmd = c;
                p->state = REQUEST_RSV;
                break;

            case REQUEST_RSV:
                if (c != 0x00) {
                    p->state = REQUEST_ERROR;
                    if (errored != NULL) {
                        *errored = true;
                    }
                    return p->state;
                }
                p->state = REQUEST_ATYP;
                break;

            case REQUEST_ATYP:
                p->atyp = c;
                if (c == 0x01) {
                    p->expected_len = 4;
                    p->addr_len = 0;
                    p->state = REQUEST_DSTADDR;
                } else if (c == 0x04) {
                    p->expected_len = 16;
                    p->addr_len = 0;
                    p->state = REQUEST_DSTADDR;
                } else if (c == 0x03) {
                    p->addr_len = 0;
                    p->has_addr_len = false;
                    p->state = REQUEST_ADDRLEN;
                } else {
                    p->state = REQUEST_ERROR;
                    if (errored != NULL) {
                        *errored = true;
                    }
                    return p->state;
                }
                break;

            case REQUEST_ADDRLEN:
                p->expected_len = c;
                p->addr_len = 0;
                p->has_addr_len = true;
                p->state = REQUEST_DSTADDR;
                break;

            case REQUEST_DSTADDR:
                p->addr[p->addr_len++] = c;
                if (p->addr_len == p->expected_len) {
                    p->port = 0;
                    p->port_len = 0;
                    p->state = REQUEST_DSTPORT;
                    return p->state;
                }
                break;

            case REQUEST_DSTPORT:
                p->port = (uint16_t)((p->port << 8) | c);
                p->port_len++;

                if (p->port_len == 2) {
                    p->state = REQUEST_DONE;
                    return p->state;
                }
                break;

            case REQUEST_DONE:
            case REQUEST_ERROR:
                return p->state;
        }
    }

    return p->state;
}

bool request_is_done(enum request_state st, bool *errored) {
    bool is_done = false;

    switch (st) {
        case REQUEST_DONE:
            is_done = true;
            if (errored != NULL) {
                *errored = false;
            }
            break;
        case REQUEST_ERROR:
            is_done = true;
            if (errored != NULL) {
                *errored = true;
            }
            break;
        default:
            is_done = false;
            if (errored != NULL) {
                *errored = false;
            }
            break;
    }

    return is_done;
}

int request_marshall_reply(buffer *b, uint8_t rep, uint8_t atyp, const uint8_t *addr, uint16_t port) {
    size_t space;
    uint8_t *ptr = buffer_write_ptr(b, &space);

    // Al menos 10 bytes VER(1) REP(1) RSV(1) ATYP(1) ADDR(4) PORT(2)
    if (space < 10) {
        return -1;
    }

    ptr[0] = 0x05;      // VER
    ptr[1] = rep;       // REP
    ptr[2] = 0x00;      // RSV
    ptr[3] = atyp;      // ATYP

    // IPv4 address (4 bytes)
    ptr[4] = addr[0];
    ptr[5] = addr[1];
    ptr[6] = addr[2];
    ptr[7] = addr[3];

    ptr[8] = (uint8_t)((port >> 8) & 0xFF);
    ptr[9] = (uint8_t)(port & 0xFF);

    buffer_write_adv(b, 10);
    return 0;
}

void request_close(struct request_parser *p) {
    if (p != NULL && p->parser != NULL) {
        parser_destroy(p->parser);
        p->parser = NULL;
    }
}

// ============================================================================
// ESTADOS REQUEST - Funciones de la máquina de estados
// ============================================================================

static int set_non_blocking(int fd) {
    const int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void client_request_read_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    d->rb = &conn->read_buf;
    d->wb = &conn->write_buf;
    request_parser_init(&d->parser);

    selector_set_interest_key(key, OP_READ);
}

void client_request_read_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    conn->req_cmd      = d->parser.cmd;
    conn->req_atyp     = d->parser.atyp;
    conn->req_port     = d->parser.port;
    conn->req_addr_len = d->parser.addr_len;
    if (conn->req_addr_len > sizeof(conn->req_addr)) {
        conn->req_addr_len = sizeof(conn->req_addr);
    }
    if (conn->req_addr_len > 0) {
        memcpy(conn->req_addr, d->parser.addr, conn->req_addr_len);
    }

    request_close(&d->parser);
}

unsigned client_request_read_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    while (true) {
        bool error = false;
        enum request_state st = request_consume(d->rb, &d->parser, &error);

        if (request_is_done(st, &error)) {
            if (error) {
                return C_ERROR;
            }
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return C_ERROR;
            }
            return C_REQUEST_WRITE;
        }

        if (buffer_can_read(d->rb)) {
            continue;
        }

        size_t space;
        uint8_t *ptr = buffer_write_ptr(d->rb, &space);
        if (space == 0) {
            return C_ERROR;
        }

        const ssize_t n = recv(key->fd, ptr, space, 0);
        if (n > 0) {
            buffer_write_adv(d->rb, (size_t)n);
            continue;
        }

        if (n == 0) {
            return C_ERROR;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return C_REQUEST_READ;
        }
        return C_ERROR;
    }
}

void client_request_write_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;

    buffer_reset(&conn->write_buf);
    conn->reply_ready = false;
    conn->reply_sent = false;

    if (conn->req_cmd != 0x01) {
        uint8_t addr[4] = {0, 0, 0, 0};
        client_set_reply(conn, 0x07, 0x01, addr, 0);
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        return;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", conn->req_port);

    int gai = 0;
    if (conn->req_atyp == 0x03) {
        char host[256];
        memcpy(host, conn->req_addr, conn->req_addr_len);
        host[conn->req_addr_len] = '\0';
        gai = getaddrinfo(host, portstr, &hints, &result);
    } else if (conn->req_atyp == 0x01) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, conn->req_addr, ip, sizeof(ip));
        gai = getaddrinfo(ip, portstr, &hints, &result);
    } else if (conn->req_atyp == 0x04) {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, conn->req_addr, ip, sizeof(ip));
        gai = getaddrinfo(ip, portstr, &hints, &result);
    } else {
        uint8_t addr[4] = {0, 0, 0, 0};
        client_set_reply(conn, 0x08, 0x01, addr, 0);
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        return;
    }

    if (gai != 0 || result == NULL) {
        uint8_t addr[4] = {0, 0, 0, 0};
        client_set_reply(conn, 0x04, 0x01, addr, 0);
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        if (result != NULL) {
            freeaddrinfo(result);
        }
        return;
    }

    memcpy(&conn->origin_addr, result->ai_addr, result->ai_addrlen);
    conn->origin_addr_len = result->ai_addrlen;
    freeaddrinfo(result);

    const int fd = socket(conn->origin_addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        uint8_t addr[4] = {0, 0, 0, 0};
        client_set_reply(conn, 0x01, 0x01, addr, 0);
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        return;
    }

    if (set_non_blocking(fd) == -1) {
        close(fd);
        uint8_t addr[4] = {0, 0, 0, 0};
        client_set_reply(conn, 0x01, 0x01, addr, 0);
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        return;
    }

    conn->origin_fd = fd;
    const int r = connect(fd, (struct sockaddr *)&conn->origin_addr, conn->origin_addr_len);
    if (r == 0) {
        if (selector_register(key->s, fd, socks5_get_handler(), OP_WRITE, conn) != SELECTOR_SUCCESS) {
            close(fd);
            conn->origin_fd = -1;
            uint8_t addr[4] = {0, 0, 0, 0};
            client_set_reply(conn, 0x01, 0x01, addr, 0);
            selector_set_interest(key->s, conn->client_fd, OP_WRITE);
            return;
        }
        conn->reply_code = 0x00;
        prepare_bound_addr(conn);
        conn->reply_ready = true;
        conn->origin_stm.current = conn->origin_stm.states + O_CONNECTING;
        if (conn->origin_stm.current->on_arrival != NULL) {
            struct selector_key origin_key = {
                .s = key->s,
                .fd = fd,
                .data = conn,
            };
            conn->origin_stm.current->on_arrival(O_CONNECTING, &origin_key);
        }
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        selector_set_interest(key->s, fd, OP_NOOP);
        return;
    }

    if (r < 0 && errno == EINPROGRESS) {
        if (selector_register(key->s, fd, socks5_get_handler(), OP_WRITE, conn) != SELECTOR_SUCCESS) {
            close(fd);
            conn->origin_fd = -1;
            uint8_t addr[4] = {0, 0, 0, 0};
            client_set_reply(conn, 0x01, 0x01, addr, 0);
            selector_set_interest(key->s, conn->client_fd, OP_WRITE);
            return;
        }
        selector_set_interest(key->s, conn->client_fd, OP_NOOP);
        return;
    }

    close(fd);
    conn->origin_fd = -1;
    uint8_t addr[4] = {0, 0, 0, 0};
    client_set_reply(conn, 0x01, 0x01, addr, 0);
    selector_set_interest(key->s, conn->client_fd, OP_WRITE);
}

unsigned client_request_write_on_read_ready(struct selector_key *key) {
    (void)key;
    return C_REQUEST_WRITE;
}

unsigned client_request_write_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (conn->reply_ready) {
        return C_REPLY;
    }
    selector_set_interest_key(key, OP_NOOP);
    return C_REQUEST_WRITE;
}

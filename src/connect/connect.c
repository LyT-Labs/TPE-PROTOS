#include "connect.h"
#include "../socks5/socks5.h"
#include "../tunnel/tunnel.h"
#include <sys/socket.h>
#include <errno.h>

// ============================================================================
// ESTADOS DE CONEXION AL ORIGIN
// ============================================================================

void origin_connect_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    selector_set_interest_key(key, OP_WRITE);
}

unsigned origin_connect_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    int err = 0;
    socklen_t len = sizeof(err);

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        return O_ERROR;
    }

    if (err != 0) {
        uint8_t addr[4] = {0, 0, 0, 0};
        client_set_reply(conn, 0x05, 0x01, addr, 0);
        conn->reply_ready = true;
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        selector_set_interest_key(key, OP_NOOP);
        return O_CONNECTING;
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

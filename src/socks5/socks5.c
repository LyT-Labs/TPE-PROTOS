#include "socks5.h"
#include "../hello/hello.h"
#include "../request/request.h"
#include "../connect/connect.h"
#include "../tunnel/tunnel.h"
#include "../helpers/metrics.h"
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_block(struct selector_key *key);
static void socks5_close(struct selector_key *key);

static bool is_client_fd(const struct socks5_conn *conn, int fd);
static bool is_origin_fd(const struct socks5_conn *conn, int fd);

static const struct state_definition client_states[] = {
    [C_HELLO_READ] = {
        .state          = C_HELLO_READ,
        .on_arrival     = client_hello_read_on_arrival,
        .on_departure   = client_hello_read_on_departure,
        .on_read_ready  = client_hello_read_on_read_ready,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
    [C_HELLO_WRITE] = {
        .state          = C_HELLO_WRITE,
        .on_arrival     = client_hello_write_on_arrival,
        .on_departure   = client_hello_write_on_departure,
        .on_read_ready  = NULL,
        .on_write_ready = client_hello_write_on_write_ready,
        .on_block_ready = NULL,
    },
    [C_AUTH_READ] = {
        .state          = C_AUTH_READ,
        .on_arrival     = client_auth_read_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = client_auth_read_on_read_ready,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
    [C_AUTH_WRITE] = {
        .state          = C_AUTH_WRITE,
        .on_arrival     = client_auth_write_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = NULL,
        .on_write_ready = client_auth_write_on_write_ready,
        .on_block_ready = NULL,
    },
    [C_REQUEST_READ] = {
        .state          = C_REQUEST_READ,
        .on_arrival     = client_request_read_on_arrival,
        .on_departure   = client_request_read_on_departure,
        .on_read_ready  = client_request_read_on_read_ready,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
    [C_REQUEST_WRITE] = {
        .state          = C_REQUEST_WRITE,
        .on_arrival     = client_request_write_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = client_request_write_on_read_ready,
        .on_write_ready = client_request_write_on_write_ready,
        .on_block_ready = NULL,
    },
    [C_REPLY] = {
        .state          = C_REPLY,
        .on_arrival     = client_reply_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = client_reply_on_read_ready,
        .on_write_ready = client_reply_on_write_ready,
        .on_block_ready = NULL,
    },
    [C_DONE] = {
        .state          = C_DONE,
        .on_arrival     = client_done_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = NULL,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
    [C_ERROR] = {
        .state          = C_ERROR,
        .on_arrival     = client_error_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = NULL,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
};

static const struct state_definition origin_states[] = {
    [O_CONNECT] = {
        .state          = O_CONNECT,
        .on_arrival     = origin_connect_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = NULL,
        .on_write_ready = origin_connect_on_write_ready,
        .on_block_ready = NULL,
    },
    [O_CONNECTING] = {
        .state          = O_CONNECTING,
        .on_arrival     = origin_connecting_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = origin_connecting_on_read_ready,
        .on_write_ready = origin_connecting_on_write_ready,
        .on_block_ready = NULL,
    },
    [O_TUNNEL] = {
        .state          = O_TUNNEL,
        .on_arrival     = origin_tunnel_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = origin_tunnel_read,
        .on_write_ready = origin_tunnel_write,
        .on_block_ready = NULL,
    },
    [O_DONE] = {
        .state          = O_DONE,
        .on_arrival     = origin_done_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = NULL,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
    [O_ERROR] = {
        .state          = O_ERROR,
        .on_arrival     = origin_error_on_arrival,
        .on_departure   = NULL,
        .on_read_ready  = NULL,
        .on_write_ready = NULL,
        .on_block_ready = NULL,
    },
};

struct socks5_conn *socks5_new(int client_fd) {
    struct socks5_conn *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));
    conn->client_fd = client_fd;
    conn->origin_fd = -1;
    conn->closed = false;
    conn->reply_ready = false;
    conn->reply_sent = false;
    conn->client_read_closed = false;
    conn->origin_read_closed = false;

    buffer_init(&conn->read_buf, sizeof(conn->read_raw), conn->read_raw);
    buffer_init(&conn->write_buf, sizeof(conn->write_raw), conn->write_raw);
    buffer_init(&conn->client_to_origin_buf,
                sizeof(conn->client_to_origin_raw),
                conn->client_to_origin_raw);
    buffer_init(&conn->origin_to_client_buf,
                sizeof(conn->origin_to_client_raw),
                conn->origin_to_client_raw);

    conn->chan_c2o.src_fd = &conn->client_fd;
    conn->chan_c2o.dst_fd = &conn->origin_fd;
    conn->chan_c2o.dst_buffer = &conn->client_to_origin_buf;
    conn->chan_c2o.read_enabled = true;
    conn->chan_c2o.write_enabled = false;
    conn->chan_c2o.direction = C2O;

    conn->chan_o2c.src_fd = &conn->origin_fd;
    conn->chan_o2c.dst_fd = &conn->client_fd;
    conn->chan_o2c.dst_buffer = &conn->origin_to_client_buf;
    conn->chan_o2c.read_enabled = true;
    conn->chan_o2c.write_enabled = false;
    conn->chan_o2c.direction = O2C;

    strcpy(conn->username, "anonymous");
    conn->method_chosen = 0xFF;

    conn->sniff_protocol = PROTO_NONE;
    pop3_sniffer_init(&conn->pop3_state);
    http_sniffer_init(&conn->http_state);
    conn->credentials_logged = false;

    conn->client_stm.initial   = C_HELLO_READ;
    conn->client_stm.max_state = (sizeof(client_states) / sizeof(client_states[0])) - 1;
    conn->client_stm.states    = client_states;
    stm_init(&conn->client_stm);

    conn->origin_stm.initial   = O_CONNECT;
    conn->origin_stm.max_state = (sizeof(origin_states) / sizeof(origin_states[0])) - 1;
    conn->origin_stm.states    = origin_states;
    stm_init(&conn->origin_stm);

    struct socks5_metrics *m = metrics_get();
    m->total_connections++;
    m->current_connections++;
    
    if (m->current_connections > m->max_concurrent_connections) {
        m->max_concurrent_connections = m->current_connections;
    }

    return conn;
}

void socks5_destroy(struct socks5_conn *conn) {
    if (conn == NULL) {
        return;
    }

    struct socks5_metrics *m = metrics_get();
    if (m->current_connections > 0) {
        m->current_connections--;
    }

    free(conn);
}

static bool is_client_fd(const struct socks5_conn *conn, int fd) {
    return conn->client_fd == fd;
}

static bool is_origin_fd(const struct socks5_conn *conn, int fd) {
    return conn->origin_fd == fd;
}

static bool client_terminal(unsigned st) {
    return st == C_DONE || st == C_ERROR;
}

static bool origin_terminal(unsigned st) {
    return st == O_DONE || st == O_ERROR;
}

static void socks5_read(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (conn == NULL || conn->closed) {
        return;
    }

    unsigned st = C_ERROR;
    if (is_client_fd(conn, key->fd)) {
        st = stm_handler_read(&conn->client_stm, key);
        if (client_terminal(st)) {
            socks5_close(key);
        }
    } else if (is_origin_fd(conn, key->fd)) {
        st = stm_handler_read(&conn->origin_stm, key);
        if (origin_terminal(st)) {
            socks5_close(key);
        }
    }
}

static void socks5_write(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (conn == NULL || conn->closed) {
        return;
    }

    unsigned st = C_ERROR;
    if (is_client_fd(conn, key->fd)) {
        st = stm_handler_write(&conn->client_stm, key);
        if (client_terminal(st)) {
            socks5_close(key);
        }
    } else if (is_origin_fd(conn, key->fd)) {
        st = stm_handler_write(&conn->origin_stm, key);
        if (origin_terminal(st)) {
            socks5_close(key);
        }
    }
}

static void socks5_block(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (conn == NULL || conn->closed) {
        return;
    }

    unsigned st = C_ERROR;
    if (is_client_fd(conn, key->fd)) {
        st = stm_handler_block(&conn->client_stm, key);
        if (client_terminal(st)) {
            socks5_close(key);
        }
    } else if (is_origin_fd(conn, key->fd)) {
        st = stm_handler_block(&conn->origin_stm, key);
        if (origin_terminal(st)) {
            socks5_close(key);
        }
    }
}

static void socks5_close(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (conn == NULL || conn->closed) {
        return;
    }

    conn->closed = true;

    if (conn->addrinfo_list != NULL) {
        freeaddrinfo(conn->addrinfo_list);
        conn->addrinfo_list = NULL;
        conn->addrinfo_current = NULL;
    }

    struct socks5_metrics *m = metrics_get();
    if (m->current_connections > 0) {
        m->current_connections--;
    }

    const int cfd = conn->client_fd;
    const int ofd = conn->origin_fd;

    conn->client_fd = -1;
    conn->origin_fd = -1;

    if (ofd != -1) {
        selector_unregister_fd(key->s, ofd);
        close(ofd);
    }
    if (cfd != -1) {
        selector_unregister_fd(key->s, cfd);
        close(cfd);
    }

    free(conn);
    key->data = NULL;
}

static const struct fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_block = socks5_block,
    .handle_close = NULL,
};

const struct fd_handler *socks5_get_handler(void) {
    return &socks5_handler;
}

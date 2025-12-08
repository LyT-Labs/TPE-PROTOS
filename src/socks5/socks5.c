#include "socks5.h"
#include "../hello/hello.h"
#include "../request/request.h"

static void hello_read_on_arrival(unsigned state, struct selector_key *key);
static void hello_read_on_departure(unsigned state, struct selector_key *key);
static unsigned hello_read_on_read_ready(struct selector_key *key);

static void hello_write_on_arrival(unsigned state, struct selector_key *key);
static void hello_write_on_departure(unsigned state, struct selector_key *key);
static unsigned hello_write_on_write_ready(struct selector_key *key);

static void     request_read_on_arrival(unsigned state, struct selector_key *key);
static void     request_read_on_departure(unsigned state, struct selector_key *key);
static unsigned request_read_on_read_ready(struct selector_key *key);

static void     request_write_on_arrival(unsigned state, struct selector_key *key);
static void     request_write_on_departure(unsigned state, struct selector_key *key);
static unsigned request_write_on_write_ready(struct selector_key *key);

static void done_on_arrival(const unsigned state, struct selector_key *key);
static void error_on_arrival(const unsigned state, struct selector_key *key);


static const struct state_definition socks5_states[] = {

    [S5_HELLO_READ] = {
        .state            = S5_HELLO_READ,
        .on_arrival       = hello_read_on_arrival,
        .on_departure     = hello_read_on_departure,
        .on_read_ready    = hello_read_on_read_ready,
        .on_write_ready   = NULL,
        .on_block_ready   = NULL,
    },

    [S5_HELLO_WRITE] = {
        .state            = S5_HELLO_WRITE,
        .on_arrival       = hello_write_on_arrival,
        .on_departure     = hello_write_on_departure,
        .on_read_ready    = NULL,
        .on_write_ready   = hello_write_on_write_ready,
        .on_block_ready   = NULL,
    },

    [S5_REQUEST_READ] = {
        .state            = S5_REQUEST_READ,
        .on_arrival       = request_read_on_arrival,
        .on_departure     = request_read_on_departure,
        .on_read_ready    = request_read_on_read_ready,
        .on_write_ready   = NULL,
        .on_block_ready   = NULL,
    },

    [S5_REQUEST_WRITE] = {
        .state            = S5_REQUEST_WRITE,
        .on_arrival       = request_write_on_arrival,
        .on_departure     = request_write_on_departure,
        .on_read_ready    = NULL,
        .on_write_ready   = request_write_on_write_ready,
        .on_block_ready   = NULL,
    },

    [S5_DONE] = {
        .state            = S5_DONE,
        .on_arrival       = done_on_arrival,
        .on_departure     = NULL,
        .on_read_ready    = NULL,
        .on_write_ready   = NULL,
        .on_block_ready   = NULL,
    },

    [S5_ERROR] = {
        .state            = S5_ERROR,
        .on_arrival       = error_on_arrival,
        .on_departure     = NULL,
        .on_read_ready    = NULL,
        .on_write_ready   = NULL,
        .on_block_ready   = NULL,
    },
};


struct socks5_conn *socks5_new(int client_fd) {
    struct socks5_conn *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }

    conn->client_fd = client_fd;
    conn->origin_fd = -1;

    buffer_init(&conn->read_buf,
                sizeof(conn->read_raw),
                conn->read_raw);
    buffer_init(&conn->write_buf,
                sizeof(conn->write_raw),
                conn->write_raw);

    conn->stm.initial   = S5_HELLO_READ;
    conn->stm.max_state = (sizeof(socks5_states) / sizeof(socks5_states[0])) - 1;
    conn->stm.states    = socks5_states;
    stm_init(&conn->stm);

    return conn;
}

void socks5_destroy(struct socks5_conn *conn) {
    if (conn == NULL) {
        return;
    }

    if (conn->client_fd != -1) {
        close(conn->client_fd);
        conn->client_fd = -1;
    }

    if (conn->origin_fd != -1) {
        close(conn->origin_fd);
        conn->origin_fd = -1;
    }

    free(conn);
}

static void socks5_handle_read(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const unsigned st = stm_handler_read(&conn->stm, key);

    if (st == S5_DONE || st == S5_ERROR) {
        selector_unregister_fd(key->s, key->fd);
        key->data = NULL;
        return;
    }
}

static void socks5_handle_write(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const unsigned st = stm_handler_write(&conn->stm, key);

    if (st == S5_DONE || st == S5_ERROR) {
        selector_unregister_fd(key->s, key->fd);
        key->data = NULL;
        return;
    }
}

static void socks5_handle_block(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const unsigned st = stm_handler_block(&conn->stm, key);

    if (st == S5_DONE || st == S5_ERROR) {
        selector_unregister_fd(key->s, key->fd);
        key->data = NULL;
        return;
    }
}

static void socks5_handle_close(struct selector_key *key) {
    struct socks5_conn *conn = key->data;

    printf("[CLOSE] cerrando fd=%d\n", key->fd);

    if (conn != NULL) {
        socks5_destroy(conn);
        key->data = NULL;
    }
}


static const struct fd_handler socks5_handler = {
    .handle_read  = socks5_handle_read,
    .handle_write = socks5_handle_write,
    .handle_block = socks5_handle_block,
    .handle_close = socks5_handle_close,
};

const struct fd_handler *socks5_get_handler(void) {
    return &socks5_handler;
}

// ============================================================================
// HELLO_READ
// ============================================================================

static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected = p->data;

    if (SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
        *selected = method;
    }
}

static void hello_read_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;

    printf("[HELLO_READ] arrival (fd=%d)\n", key->fd);

    // Inicializar el estado de hello
    d->rb = &conn->read_buf;
    d->wb = &conn->write_buf;
    d->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
    
    // Inicializar el parser
    hello_parser_init(&d->parser);
    d->parser.data = &d->method;
    d->parser.on_authentication_method = on_hello_method;

    selector_set_interest_key(key, OP_READ);
}


static void hello_read_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;
    
    printf("[HELLO_READ] departure (fd=%d)\n", key->fd);
    
    // Limpiar recursos del parser
    hello_close(&d->parser);
}

static unsigned hello_process(const struct hello_st *d);

static unsigned hello_read_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;
    unsigned ret = S5_HELLO_READ;
    bool error = false;

    printf("[HELLO_READ] read_ready (fd=%d)\n", key->fd);

    // 1) Leer del socket al buffer
    size_t space;
    uint8_t *ptr = buffer_write_ptr(d->rb, &space);

    if (space == 0) {
        fprintf(stderr, "[HELLO_READ] buffer de lectura lleno (fd=%d)\n", key->fd);
        return S5_ERROR;
    }

    ssize_t n = recv(key->fd, ptr, space, 0);
    if (n == 0) {
        printf("[HELLO_READ] cliente cerró la conexión (fd=%d)\n", key->fd);
        return S5_ERROR;
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return S5_HELLO_READ;
        }
        perror("[HELLO_READ] recv");
        return S5_ERROR;
    }

    buffer_write_adv(d->rb, (size_t)n);

    // 2) Consumir bytes con el parser
    const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
    
    if (hello_is_done(st, &error)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
            ret = hello_process(d);
        } else {
            ret = S5_ERROR;
        }
    }

    return error ? S5_ERROR : ret;
}

static unsigned hello_process(const struct hello_st *d) {
    unsigned ret = S5_HELLO_WRITE;

    uint8_t m = d->method;
    const uint8_t r = (m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) ? SOCKS_HELLO_NO_ACCEPTABLE_METHODS : SOCKS_HELLO_NOAUTHENTICATION_REQUIRED; //TODO: corregir en un futuro
    
    if (-1 == hello_marshall(d->wb, r)) {
        ret = S5_ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret = S5_ERROR;
    }
    
    return ret;
}



// ============================================================================
// HELLO_WRITE
// ============================================================================

static void hello_write_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    printf("[HELLO_WRITE] arrival (fd=%d)\n", key->fd);
    selector_set_interest_key(key, OP_WRITE);
}


static void hello_write_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    printf("[HELLO_WRITE] departure (fd=%d)\n", key->fd);
    
    // Resetear buffers para próximos estados
    buffer_reset(&conn->write_buf);
}

static unsigned hello_write_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;

    printf("[HELLO_WRITE] write_ready (fd=%d)\n", key->fd);

    if (!buffer_can_read(d->wb)) {
        return S5_ERROR;
    }

    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(d->wb, &nbytes);

    ssize_t n = send(key->fd, ptr, nbytes, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return S5_HELLO_WRITE;
        }
        perror("[HELLO_WRITE] send");
        return S5_ERROR;
    }

    buffer_read_adv(d->wb, (size_t)n);

    // ¿Quedan bytes por enviar?
    if (buffer_can_read(d->wb)) {
        return S5_HELLO_WRITE;
    }

    // Si el método seleccionado es NO_ACCEPTABLE_METHODS, error
    if (d->method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
        return S5_ERROR;
    }

    // Pasar al estado REQUEST_READ
    return S5_REQUEST_READ;
}

// ============================================================================
// REQUEST_READ
// ============================================================================

static void request_read_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    printf("[REQUEST_READ] arrival (fd=%d)\n", key->fd);

    d->rb = &conn->read_buf;
    d->wb = &conn->write_buf;

    request_parser_init(&d->parser);

    selector_set_interest_key(key, OP_READ);
}

static void request_read_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;
    
    printf("[REQUEST_READ] departure (fd=%d)\n", key->fd);
    
    request_close(&d->parser);
}

static unsigned request_read_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    printf("[REQUEST_READ] read_ready (fd=%d)\n", key->fd);

    size_t space;
    uint8_t *ptr = buffer_write_ptr(d->rb, &space);

    if (space == 0) {
        fprintf(stderr, "[REQUEST_READ] buffer de lectura lleno (fd=%d)\n", key->fd);
        return S5_ERROR;
    }

    ssize_t n = recv(key->fd, ptr, space, 0);
    if (n == 0) {
        printf("[REQUEST_READ] cliente cerró la conexión (fd=%d)\n", key->fd);
        return S5_ERROR;
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return S5_REQUEST_READ;
        }
        perror("[REQUEST_READ] recv");
        return S5_ERROR;
    }

    buffer_write_adv(d->rb, (size_t)n);

    bool error = false;
    enum request_state st = request_consume(d->rb, &d->parser, &error);

    if (request_is_done(st, &error)) {
        if (error) {
            return S5_ERROR;
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return S5_ERROR;
        }
        return S5_REQUEST_WRITE;
    }

    return S5_REQUEST_READ;
}

// ============================================================================
// REQUEST_WRITE
// ============================================================================

static void request_write_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    printf("[REQUEST_WRITE] arrival (fd=%d)\n", key->fd);
    selector_set_interest_key(key, OP_WRITE);
}

static void request_write_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    printf("[REQUEST_WRITE] departure (fd=%d)\n", key->fd);
}

static unsigned request_write_on_write_ready(struct selector_key *key) {
    printf("[REQUEST_WRITE] write_ready (fd=%d)\n", key->fd);

    // Todavía no enviamos respuesta real; devolver DONE como stub.
    return S5_DONE;
}

// ============================================================================
// DONE / ERROR
// ============================================================================

static void done_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    printf("[DONE] conexion finalizada (fd=%d)\n", key->fd);

    // Liberación a cargo de socks5_destroy
}

static void error_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    printf("[ERROR] conexion fallida (fd=%d)\n", key->fd);

    // Liberación a cargo de socks5_destroy
}

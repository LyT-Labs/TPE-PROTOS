#include "socks5.h"
#include "../hello/hello.h"
#include "../request/request.h"
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>

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

static void     connect_on_arrival(unsigned state, struct selector_key *key);
static unsigned connect_on_write_ready(struct selector_key *key);

static void     connecting_on_arrival(unsigned state, struct selector_key *key);
static unsigned connecting_on_write_ready(struct selector_key *key);

static void done_on_arrival(const unsigned state, struct selector_key *key);
static void error_on_arrival(const unsigned state, struct selector_key *key);

static void     tunnel_on_arrival(unsigned state, struct selector_key *key);
static unsigned tunnel_read(struct selector_key *key);
static unsigned tunnel_write(struct selector_key *key);

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_block(struct selector_key *key);
static void socks5_close(struct selector_key *key);
static void socks5_handle_close(struct selector_key *key);


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

    [S5_CONNECT] = {
        .state            = S5_CONNECT,
        .on_arrival       = connect_on_arrival,
        .on_departure     = NULL,
        .on_read_ready    = NULL,
        .on_write_ready   = connect_on_write_ready,
        .on_block_ready   = NULL,
    },

    [S5_CONNECTING] = {
        .state            = S5_CONNECTING,
        .on_arrival       = connecting_on_arrival,
        .on_departure     = NULL,
        .on_read_ready    = NULL,
        .on_write_ready   = connecting_on_write_ready,
        .on_block_ready   = NULL,
    },

    [S5_TUNNEL] = {
        .state            = S5_TUNNEL,
        .on_arrival       = tunnel_on_arrival,
        .on_departure     = NULL,
        .on_read_ready    = tunnel_read,
        .on_write_ready   = tunnel_write,
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

    // Inicializar buffers para el túnel
    buffer_init(&conn->client_to_origin_buf,
                sizeof(conn->client_to_origin_raw),
                conn->client_to_origin_raw);
    buffer_init(&conn->origin_to_client_buf,
                sizeof(conn->origin_to_client_raw),
                conn->origin_to_client_raw);

    // Inicializar flags de EOF
    conn->client_read_closed = false;
    conn->origin_read_closed = false;

    // Inicializar canal cliente → origin
    conn->chan_c2o.src_fd = &conn->client_fd;
    conn->chan_c2o.dst_fd = &conn->origin_fd;
    conn->chan_c2o.src_buffer = NULL;
    conn->chan_c2o.dst_buffer = &conn->client_to_origin_buf;
    conn->chan_c2o.read_enabled = true;
    conn->chan_c2o.write_enabled = false;

    // Inicializar canal origin → cliente
    conn->chan_o2c.src_fd = &conn->origin_fd;
    conn->chan_o2c.dst_fd = &conn->client_fd;
    conn->chan_o2c.src_buffer = NULL;
    conn->chan_o2c.dst_buffer = &conn->origin_to_client_buf;
    conn->chan_o2c.read_enabled = true;
    conn->chan_o2c.write_enabled = false;

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

static void socks5_read(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const unsigned st = stm_handler_read(&conn->stm, key);

    if (st == S5_DONE || st == S5_ERROR) {
        socks5_close(key);
    }
}

static void socks5_write(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const unsigned st = stm_handler_write(&conn->stm, key);

    if (st == S5_DONE || st == S5_ERROR) {
        socks5_close(key);
    }
}

static void socks5_block(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const unsigned st = stm_handler_block(&conn->stm, key);

    if (st == S5_DONE || st == S5_ERROR) {
        socks5_close(key);
    }
}

static void socks5_close(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    if (conn == NULL) {
        return;
    }

    int client_fd = conn->client_fd;
    int origin_fd = conn->origin_fd;

    // Marcar los fd como no válidos
    conn->client_fd = -1;
    conn->origin_fd = -1;

    // Desregistrar y cerrar origin_fd si existe
    if (origin_fd != -1) {
        selector_unregister_fd(key->s, origin_fd);
        // selector_unregister_fd ya hace close() internamente
        close(origin_fd);
    }

    // Desregistrar y cerrar client_fd si existe
    if (client_fd != -1) {
        selector_unregister_fd(key->s, client_fd);
        close(client_fd);
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
    
    // Copiar los datos parseados del REQUEST hacia la conexión
    conn->req_cmd      = d->parser.cmd;
    conn->req_atyp     = d->parser.atyp;
    conn->req_port     = d->parser.port;
    conn->req_addr_len = d->parser.addr_len;

    // Copiar la dirección (IPv4, IPv6 o FQDN)
    if (conn->req_addr_len > sizeof(conn->req_addr)) {
        conn->req_addr_len = sizeof(conn->req_addr);
    }
    if (conn->req_addr_len > 0) {
        memcpy(conn->req_addr, d->parser.addr, conn->req_addr_len);
    }

    printf("[REQUEST_READ] cmd=0x%02x atyp=0x%02x port=%u (fd=%d)\n",
           conn->req_cmd, conn->req_atyp, conn->req_port, key->fd);
    
    request_close(&d->parser);
}

static unsigned request_read_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    printf("[REQUEST_READ] read_ready (fd=%d)\n", key->fd);

    while (true) {
        // 1) Intentar parsear todo lo que ya está en el buffer
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

        if (buffer_can_read(d->rb)) {
            continue;
        }

        // 2) Si ya no hay bytes en el buffer, recién ahí intentamos leer más
        size_t space;
        uint8_t *ptr = buffer_write_ptr(d->rb, &space);

        if (space == 0) {
            fprintf(stderr, "[REQUEST_READ] buffer de lectura lleno (fd=%d)\n", key->fd);
            return S5_ERROR;
        }

        ssize_t n = recv(key->fd, ptr, space, 0);
        if (n > 0) {
            buffer_write_adv(d->rb, (size_t)n);
            // volvemos al inicio del while: primero parseamos lo nuevo
            continue;
        }

        if (n == 0) {
            printf("[REQUEST_READ] cliente cerró la conexión (fd=%d)\n", key->fd);
            return S5_ERROR;
        }

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No hay más datos *del socket*, y tampoco en el buffer,
                // así que esperamos otro read_ready.
                return S5_REQUEST_READ;
            }
            perror("[REQUEST_READ] recv");
            return S5_ERROR;
        }
    }
}


// ============================================================================
// REQUEST_WRITE
// ============================================================================

static void request_write_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    printf("[REQUEST_WRITE] arrival (fd=%d) - pasando directo a CONNECT\n", key->fd);
    
    // Ya no enviamos el REP aquí, pasamos directo a CONNECT
    selector_set_interest_key(key, OP_WRITE);
}

static void request_write_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    printf("[REQUEST_WRITE] departure (fd=%d)\n", key->fd);
}

static unsigned request_write_on_write_ready(struct selector_key *key) {
    (void)key;
    // Ya no enviamos nada aquí, pasamos directo a CONNECT
    return S5_CONNECT;
}

// ============================================================================
// CONNECT
// ============================================================================

static void connect_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;

    printf("[CONNECT] arrival (fd=%d)\n", key->fd);

    // 1) validar comando
    if (conn->req_cmd != 0x01) {
        printf("[CONNECT] cmd no soportado (0x%02x)\n", conn->req_cmd);
        // Enviar REP = 0x07 (Command not supported)
        struct request_st *d = &conn->client.request;
        uint8_t addr[4] = {0, 0, 0, 0};
        request_marshall_reply(d->wb, 0x07, 0x01, addr, 0);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    // 2) resolver dirección (bloqueante)
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = 0;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", conn->req_port);

    if (conn->req_atyp == 0x03) {
        // FQDN: el addr es un string NO terminado en \0 → crearlo
        char host[256];
        memcpy(host, conn->req_addr, conn->req_addr_len);
        host[conn->req_addr_len] = '\0';

        printf("[CONNECT] resolviendo FQDN: %s:%s\n", host, portstr);
        gai = getaddrinfo(host, portstr, &hints, &result);
    } else if (conn->req_atyp == 0x01) {
        // IPv4
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, conn->req_addr, ip, sizeof(ip));
        printf("[CONNECT] resolviendo IPv4: %s:%s\n", ip, portstr);
        gai = getaddrinfo(ip, portstr, &hints, &result);
    } else if (conn->req_atyp == 0x04) {
        // IPv6
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, conn->req_addr, ip, sizeof(ip));
        printf("[CONNECT] resolviendo IPv6: %s:%s\n", ip, portstr);
        gai = getaddrinfo(ip, portstr, &hints, &result);
    } else {
        printf("[CONNECT] ATYP no soportado (0x%02x)\n", conn->req_atyp);
        struct request_st *d = &conn->client.request;
        uint8_t addr[4] = {0, 0, 0, 0};
        request_marshall_reply(d->wb, 0x08, 0x01, addr, 0);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    if (gai != 0 || result == NULL) {
        printf("[CONNECT] getaddrinfo fallo: %s\n", gai_strerror(gai));
        struct request_st *d = &conn->client.request;
        uint8_t addr[4] = {0, 0, 0, 0};
        request_marshall_reply(d->wb, 0x01, 0x01, addr, 0);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    // copiar dirección a conn (el puerto ya viene resuelto de getaddrinfo)
    memcpy(&conn->origin_addr, result->ai_addr, result->ai_addrlen);
    conn->origin_addr_len = result->ai_addrlen;

    freeaddrinfo(result);

    // 3) crear origin_fd
    int fd = socket(conn->origin_addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[CONNECT] socket");
        struct request_st *d = &conn->client.request;
        uint8_t addr[4] = {0, 0, 0, 0};
        request_marshall_reply(d->wb, 0x01, 0x01, addr, 0);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    // no bloqueante
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        perror("[CONNECT] fcntl O_NONBLOCK");
        close(fd);
        struct request_st *d = &conn->client.request;
        uint8_t addr[4] = {0, 0, 0, 0};
        request_marshall_reply(d->wb, 0x01, 0x01, addr, 0);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    conn->origin_fd = fd;

    // 4) iniciar connect
    int r = connect(fd, (struct sockaddr *)&conn->origin_addr, conn->origin_addr_len);
    if (r == 0) {
        printf("[CONNECT] connect inmediato OK\n");
        // Conexión inmediata → registrar origin_fd con socks5_handler
        if (selector_register(key->s, fd, &socks5_handler, OP_WRITE, conn) != SELECTOR_SUCCESS) {
            perror("[CONNECT] selector_register");
            close(fd);
            conn->origin_fd = -1;
            struct request_st *d = &conn->client.request;
            uint8_t addr[4] = {0, 0, 0, 0};
            request_marshall_reply(d->wb, 0x01, 0x01, addr, 0);
            selector_set_interest_key(key, OP_WRITE);
            return;
        }
        // El write_ready handler hará la transición a CONNECTING
        selector_set_interest_key(key, OP_NOOP);
        return;
    }

    if (r < 0 && errno == EINPROGRESS) {
        printf("[CONNECT] connect en progreso (fd=%d → origin_fd=%d)\n", key->fd, fd);
        // registrar origin_fd con socks5_handler para OP_WRITE
        if (selector_register(key->s, fd, &socks5_handler, OP_WRITE, conn) != SELECTOR_SUCCESS) {
            perror("[CONNECT] selector_register");
            close(fd);
            conn->origin_fd = -1;
            struct request_st *d = &conn->client.request;
            uint8_t addr[4] = {0, 0, 0, 0};
            request_marshall_reply(d->wb, 0x01, 0x01, addr, 0);
            selector_set_interest_key(key, OP_WRITE);
            return;
        }
        // Dejar de monitorear el client_fd por ahora
        selector_set_interest_key(key, OP_NOOP);
        return;
    }

    printf("[CONNECT] error inmediato: %s\n", strerror(errno));
    close(fd);
    conn->origin_fd = -1;
    struct request_st *d = &conn->client.request;
    uint8_t addr[4] = {0, 0, 0, 0};
    request_marshall_reply(d->wb, 0x01, 0x01, addr, 0);
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned connect_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    
    // Este handler se llama cuando origin_fd está listo para escritura
    // Verificar si el evento viene del origin_fd
    if (key->fd == conn->origin_fd) {
        int err = 0;
        socklen_t len = sizeof(err);

        if (getsockopt(conn->origin_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
            perror("[CONNECT] getsockopt");
            return S5_ERROR;
        }

        if (err != 0) {
            printf("[CONNECT] fallo connect: %s\n", strerror(err));
            return S5_ERROR;
        }

        printf("[CONNECT] conectado OK (origin_fd=%d), transición a CONNECTING\n", conn->origin_fd);
        
        // Cambiar interés del client_fd para enviar el REP
        selector_set_interest(key->s, conn->client_fd, OP_WRITE);
        
        return S5_CONNECTING;
    }
    
    // Si el evento viene del client_fd (no debería pasar), mantener el estado
    return S5_CONNECT;
}



// ============================================================================
// CONNECTING
// ============================================================================

static void connecting_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    printf("[CONNECTING] arrival (fd=%d)\n", key->fd);

    // obtener ip/puerto local del origin_fd
    struct sockaddr_storage local;
    socklen_t len = sizeof(local);
    if (getsockname(conn->origin_fd, (struct sockaddr *)&local, &len) < 0) {
        perror("[CONNECTING] getsockname");
        // En caso de error, enviar respuesta con 0.0.0.0:0
        uint8_t addr[4] = {0, 0, 0, 0};
        request_marshall_reply(d->wb, 0x00, 0x01, addr, 0);
    } else {
        uint8_t addr[4] = {0, 0, 0, 0};
        uint16_t port = 0;

        if (local.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in*)&local;
            memcpy(addr, &sin->sin_addr, 4);
            port = ntohs(sin->sin_port);
        } else if (local.ss_family == AF_INET6) {
            // Para IPv6, podríamos enviar 0.0.0.0 o intentar otro formato
            // Por simplicidad, usamos 0.0.0.0
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&local;
            port = ntohs(sin6->sin6_port);
        }

        printf("[CONNECTING] BND.ADDR=%d.%d.%d.%d BND.PORT=%u\n", 
               addr[0], addr[1], addr[2], addr[3], port);
        request_marshall_reply(d->wb, 0x00, 0x01, addr, port);
    }

    // Cambiar el interés al client_fd para enviar la respuesta
    // El origin_fd está conectado pero aún no lo usaremos (túnel en siguiente paso)
    selector_set_interest(key->s, conn->client_fd, OP_WRITE);
}

static unsigned connecting_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct request_st *d = &conn->client.request;

    size_t n;
    uint8_t *ptr = buffer_read_ptr(d->wb, &n);

    if (n == 0) {
        printf("[CONNECTING] respuesta enviada completa, pasando a TUNNEL\n");
        buffer_reset(d->wb);
        return S5_TUNNEL;
    }

    ssize_t sent = send(key->fd, ptr, n, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return S5_CONNECTING;
        }
        perror("[CONNECTING] send");
        return S5_ERROR;
    }

    if (sent == 0) {
        return S5_ERROR;
    }

    buffer_read_adv(d->wb, sent);

    if (!buffer_can_read(d->wb)) {
        printf("[CONNECTING] respuesta enviada completa, pasando a TUNNEL\n");
        buffer_reset(d->wb);
        return S5_TUNNEL;
    }

    return S5_CONNECTING;
}

// ============================================================================
// TUNNEL - Sistema de canales bidireccionales
// ============================================================================

static void tunnel_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;

    printf("[TUNNEL] arrival (fd=%d)\n", key->fd);
    printf("[TUNNEL] iniciando túnel bidireccional client_fd=%d ⇄ origin_fd=%d\n",
           conn->client_fd, conn->origin_fd);

    // Habilitar lectura en ambos extremos
    selector_set_interest(key->s, conn->client_fd, OP_READ);
    selector_set_interest(key->s, conn->origin_fd, OP_READ);

    // Los canales ya están inicializados en socks5_new
    conn->chan_c2o.read_enabled = true;
    conn->chan_c2o.write_enabled = false;
    conn->chan_o2c.read_enabled = true;
    conn->chan_o2c.write_enabled = false;
}

static void channel_read(struct selector_key *key, struct data_channel *ch) {
    // Verificar si la lectura está habilitada
    if (!ch->read_enabled) {
        return;
    }

    // Obtener espacio disponible en el buffer de destino
    size_t space;
    uint8_t *write_ptr = buffer_write_ptr(ch->dst_buffer, &space);

    if (space == 0) {
        // Buffer lleno, deshabilitar lectura temporalmente
        selector_set_interest(key->s, *ch->src_fd, OP_NOOP);
        return;
    }

    // Leer datos del file descriptor origen
    ssize_t n = recv(*ch->src_fd, write_ptr, space, 0);

    if (n == 0) {
        // EOF: cerrar este lado del canal
        ch->read_enabled = false;
        shutdown(*ch->src_fd, SHUT_RD);
        if (*ch->dst_fd != -1) {
            shutdown(*ch->dst_fd, SHUT_WR);
        }
        return;
    }

    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Error real, marcar para cerrar
            ch->read_enabled = false;
        }
        return;
    }

    // Avanzar el buffer con los datos leídos
    buffer_write_adv(ch->dst_buffer, (size_t)n);

    // Habilitar escritura en el destino si hay datos pendientes
    if (buffer_can_read(ch->dst_buffer)) {
        selector_set_interest(key->s, *ch->dst_fd, OP_WRITE | OP_READ);
        ch->write_enabled = true;
    }
}

static void channel_write(struct selector_key *key, struct data_channel *ch) {
    // Verificar si hay datos para escribir
    size_t available;
    uint8_t *read_ptr = buffer_read_ptr(ch->dst_buffer, &available);

    if (available == 0) {
        // No hay datos, deshabilitar escritura
        selector_set_interest(key->s, *ch->dst_fd, OP_READ);
        ch->write_enabled = false;

        // Reactivar lectura en el origen si estaba deshabilitada
        if (ch->read_enabled) {
            selector_set_interest(key->s, *ch->src_fd, OP_READ);
        }
        return;
    }

    // Enviar datos al file descriptor destino
    ssize_t n = send(*ch->dst_fd, read_ptr, available, MSG_NOSIGNAL);

    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Error real
            ch->write_enabled = false;
        }
        return;
    }

    // Avanzar el buffer
    buffer_read_adv(ch->dst_buffer, (size_t)n);

    // Actualizar intereses según el estado del buffer
    if (buffer_can_read(ch->dst_buffer)) {
        // Aún hay datos, mantener escritura habilitada
        selector_set_interest(key->s, *ch->dst_fd, OP_WRITE | OP_READ);
    } else {
        // Buffer vacío, deshabilitar escritura y reactivar lectura
        selector_set_interest(key->s, *ch->dst_fd, OP_READ);
        ch->write_enabled = false;

        if (ch->read_enabled) {
            selector_set_interest(key->s, *ch->src_fd, OP_READ);
        }
    }
}

static unsigned tunnel_read(struct selector_key *key) {
    struct socks5_conn *conn = key->data;

    // Determinar qué canal debe leer según el fd que disparó el evento
    if (key->fd == conn->client_fd) {
        channel_read(key, &conn->chan_c2o);
    } else if (key->fd == conn->origin_fd) {
        channel_read(key, &conn->chan_o2c);
    }

    // Verificar si ambos canales están cerrados y buffers vacíos
    if (!conn->chan_c2o.read_enabled && 
        !conn->chan_o2c.read_enabled &&
        !buffer_can_read(&conn->client_to_origin_buf) &&
        !buffer_can_read(&conn->origin_to_client_buf)) {
        return S5_DONE;
    }

    return S5_TUNNEL;
}

static unsigned tunnel_write(struct selector_key *key) {
    struct socks5_conn *conn = key->data;

    // Determinar qué canal debe escribir según el fd que disparó el evento
    if (key->fd == *conn->chan_c2o.dst_fd) {
        channel_write(key, &conn->chan_c2o);
    } else if (key->fd == *conn->chan_o2c.dst_fd) {
        channel_write(key, &conn->chan_o2c);
    }

    // Verificar si ambos canales están cerrados y buffers vacíos
    if (!conn->chan_c2o.read_enabled && 
        !conn->chan_o2c.read_enabled &&
        !buffer_can_read(&conn->client_to_origin_buf) &&
        !buffer_can_read(&conn->origin_to_client_buf)) {
        return S5_DONE;
    }

    return S5_TUNNEL;
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

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include "hello.h"
#include "../socks5/socks5.h"

// ============================================================================
// Acciones para las transiciones del parser
// ============================================================================

static void hello_version_ok(struct parser_event *ret, const uint8_t c) {
    ret->type = HELLO_EVENT_VERSION_OK;
    ret->n = 1;
    ret->data[0] = c;
}

static void hello_version_bad(struct parser_event *ret, const uint8_t c) {
    ret->type = HELLO_EVENT_VERSION_BAD;
    ret->n = 1;
    ret->data[0] = c;
}

static void hello_nmethods_ok(struct parser_event *ret, const uint8_t c) {
    ret->type = HELLO_EVENT_NMETHODS_OK;
    ret->n = 1;
    ret->data[0] = c;
}

static void hello_nmethods_bad(struct parser_event *ret, const uint8_t c) {
    ret->type = HELLO_EVENT_NMETHODS_BAD;
    ret->n = 1;
    ret->data[0] = c;
}

static void hello_method(struct parser_event *ret, const uint8_t c) {
    ret->type = HELLO_EVENT_METHOD;
    ret->n = 1;
    ret->data[0] = c;
}

static void hello_done(struct parser_event *ret, const uint8_t c) {
    ret->type = HELLO_EVENT_DONE;
    ret->n = 1;
    ret->data[0] = c;
}

// ===========================================================================
// Transiciones
// ============================================================================

static const struct parser_state_transition ST_VERSION[] = {
    { .when = SOCKS_VERSION, .dest = HELLO_NMETHODS, .act1 = hello_version_ok,  .act2 = NULL },
    { .when = ANY,           .dest = HELLO_ERROR,    .act1 = hello_version_bad, .act2 = NULL },
};

static const struct parser_state_transition ST_NMETHODS[] = {
    { .when = 0x00, .dest = HELLO_ERROR,   .act1 = hello_nmethods_bad, .act2 = NULL },
    { .when = ANY,  .dest = HELLO_METHODS, .act1 = hello_nmethods_ok,  .act2 = NULL },
};

static const struct parser_state_transition ST_METHODS[] = {
    { .when = ANY, .dest = HELLO_METHODS, .act1 = hello_method, .act2 = NULL },
};

static const struct parser_state_transition *hello_states[] = {
    ST_VERSION,
    ST_NMETHODS,
    ST_METHODS,
    NULL,
    NULL,
};

static const size_t hello_states_n[] = {
    sizeof(ST_VERSION) / sizeof(ST_VERSION[0]),
    sizeof(ST_NMETHODS) / sizeof(ST_NMETHODS[0]),
    sizeof(ST_METHODS) / sizeof(ST_METHODS[0]),
    0,
    0,
};

// ============================================================================
// Definición completa del parser
// ============================================================================

static const struct parser_definition hello_parser_def = {
    .states_count = sizeof(hello_states) / sizeof(hello_states[0]),
    .states = hello_states,
    .states_n = hello_states_n,
    .start_state = HELLO_VERSION,
};

// ============================================================================
// Implementación de las funciones públicas
// ============================================================================

void hello_parser_init(struct hello_parser *p) {
    p->parser = parser_init(parser_no_classes(), &hello_parser_def);
    p->state = HELLO_VERSION;
    p->nmethods = 0;
    p->methods_read = 0;
    p->data = NULL;
    p->on_authentication_method = NULL;
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
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

        const struct parser_event *event = parser_feed(p->parser, c);

        while (event != NULL) {
            switch (event->type) {
                case HELLO_EVENT_VERSION_OK:
                    p->state = HELLO_NMETHODS;
                    break;

                case HELLO_EVENT_VERSION_BAD:
                    p->state = HELLO_ERROR;
                    if (errored != NULL) {
                        *errored = true;
                    }
                    return p->state;

                case HELLO_EVENT_NMETHODS_OK:
                    p->nmethods = event->data[0];
                    p->methods_read = 0;
                    p->state = HELLO_METHODS;
                    break;

                case HELLO_EVENT_NMETHODS_BAD:
                    p->state = HELLO_ERROR;
                    if (errored != NULL) {
                        *errored = true;
                    }
                    return p->state;

                case HELLO_EVENT_METHOD:
                    // Callback al usuario
                    if (p->on_authentication_method != NULL) {
                        p->on_authentication_method(p, event->data[0]);
                    }
                    
                    p->methods_read++;
                    
                    if (p->methods_read >= p->nmethods) {
                        if (buffer_can_read(b)) {
                            p->state = HELLO_ERROR;
                            if (errored != NULL) {
                                *errored = true;
                            }
                            return p->state;
                        }
                        
                        p->state = HELLO_DONE;
                        return p->state;
                    }
                    break;

                default:
                    break;
            }

            event = event->next;
        }

        if (p->state == HELLO_DONE || p->state == HELLO_ERROR) {
            return p->state;
        }
    }

    return p->state;
}

bool hello_is_done(const enum hello_state state, bool *error) {
    bool is_done = false;

    switch (state) {
        case HELLO_DONE:
            is_done = true;
            if (error != NULL) {
                *error = false;
            }
            break;
        case HELLO_ERROR:
            is_done = true;
            if (error != NULL) {
                *error = true;
            }
            break;
        default:
            is_done = false;
            if (error != NULL) {
                *error = false;
            }
            break;
    }

    return is_done;
}

int hello_marshall(buffer *b, const uint8_t method) {
    size_t space;
    uint8_t *ptr = buffer_write_ptr(b, &space);

    if (space < 2) {
        return -1;
    }

    ptr[0] = SOCKS_VERSION;
    ptr[1] = method;

    buffer_write_adv(b, 2);
    return 0;
}

void hello_close(struct hello_parser *p) {
    if (p != NULL && p->parser != NULL) {
        parser_destroy(p->parser);
        p->parser = NULL;
    }
}

// ============================================================================
// ESTADOS HELLO - Funciones de la máquina de estados
// ============================================================================

static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected = p->data;
    if (SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
        *selected = method;
    }
}

static unsigned client_hello_process(struct hello_st *d) {
    uint8_t final_method = d->method;
    
    if (d->method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
        final_method = 0xFF;
    }

    size_t space;
    uint8_t *ptr = buffer_write_ptr(d->wb, &space);
    
    if (space < 2) {
        return C_ERROR;
    }

    ptr[0] = SOCKS_VERSION;  // 0x05
    ptr[1] = final_method;
    buffer_write_adv(d->wb, 2);

    if (d->method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
        return C_ERROR;
    }

    return C_HELLO_WRITE;
}

void client_hello_read_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;

    d->rb = &conn->read_buf;
    d->wb = &conn->write_buf;
    d->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;

    hello_parser_init(&d->parser);
    d->parser.data = &d->method;
    d->parser.on_authentication_method = on_hello_method;

    selector_set_interest_key(key, OP_READ);
}

void client_hello_read_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;
    hello_close(&d->parser);
}

unsigned client_hello_read_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;
    unsigned ret = C_HELLO_READ;
    bool error = false;

    size_t space;
    uint8_t *ptr = buffer_write_ptr(d->rb, &space);
    if (space == 0) {
        return C_ERROR;
    }

    const ssize_t n = recv(key->fd, ptr, space, 0);
    if (n == 0) {
        return C_ERROR;
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return C_HELLO_READ;
        }
        return C_ERROR;
    }

    buffer_write_adv(d->rb, (size_t)n);

    const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
    if (hello_is_done(st, &error)) {
        if (error) {
            return C_ERROR;
        }
        
        ret = client_hello_process(d);
        if (ret == C_ERROR) {
            return C_ERROR;
        }
        
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return C_ERROR;
        }
        
        return C_HELLO_WRITE;
    }

    return error ? C_ERROR : ret;
}

void client_hello_write_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    selector_set_interest_key(key, OP_WRITE);
}

void client_hello_write_on_departure(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    buffer_reset(&conn->write_buf);
}

unsigned client_hello_write_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct hello_st *d = &conn->client.hello;

    if (!buffer_can_read(d->wb)) {
        return C_ERROR;
    }

    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(d->wb, &nbytes);

    const ssize_t n = send(key->fd, ptr, nbytes, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return C_HELLO_WRITE;
        }
        return C_ERROR;
    }

    buffer_read_adv(d->wb, (size_t)n);
    if (buffer_can_read(d->wb)) {
        return C_HELLO_WRITE;
    }

    if (d->method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
        return C_ERROR;
    }

    return C_REQUEST_READ;
}

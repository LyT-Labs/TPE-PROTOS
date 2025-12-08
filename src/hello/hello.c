#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "hello.h"

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

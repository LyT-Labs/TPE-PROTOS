#include "request.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// ============================================================================  
// Acciones de parser (por ahora vacías, solo declarar funciones estáticas)
// ============================================================================

// TODO: implementar más adelante

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
    (void)b;
    (void)rep;
    (void)atyp;
    (void)addr;
    (void)port;
    // Implementación real vendrá más adelante
    return -1;
}

void request_close(struct request_parser *p) {
    if (p != NULL && p->parser != NULL) {
        parser_destroy(p->parser);
        p->parser = NULL;
    }
}

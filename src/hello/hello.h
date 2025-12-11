#ifndef HELLO_H
#define HELLO_H

#include <stdint.h>
#include <stdbool.h>
#include "../helpers/buffer.h"
#include "../helpers/parser.h"
#include "../helpers/selector.h"

// ===========================================================================
// Constantes del protocolo SOCKS5 para el saludo
// ===========================================================================
#define SOCKS_VERSION                           0x05
#define SOCKS_HELLO_NOAUTHENTICATION_REQUIRED   0x00
#define SOCKS_HELLO_USERNAME_PASSWORD           0x02
#define SOCKS_HELLO_NO_ACCEPTABLE_METHODS       0xFF

// ===========================================================================
// Parser de hello
// ===========================================================================
enum hello_state {
    HELLO_VERSION,
    HELLO_NMETHODS,
    HELLO_METHODS,
    HELLO_DONE,
    HELLO_ERROR,
};

enum hello_event_type {
    HELLO_EVENT_VERSION_OK,
    HELLO_EVENT_VERSION_BAD,
    HELLO_EVENT_NMETHODS_OK,
    HELLO_EVENT_NMETHODS_BAD,
    HELLO_EVENT_METHOD,
    HELLO_EVENT_DONE,
};

struct hello_parser {
    struct parser *parser;
    enum hello_state state;
    uint8_t nmethods;
    uint8_t methods_read;
    void *data;
    void (*on_authentication_method)(struct hello_parser *p, const uint8_t method);
};

void hello_parser_init(struct hello_parser *p);

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored);

bool hello_is_done(const enum hello_state state, bool *error);

int hello_marshall(buffer *b, const uint8_t method);

void hello_close(struct hello_parser *p);

// ===========================================================================
// Estructuras de estado HELLO
// ===========================================================================

struct hello_st {
    buffer *rb, *wb;
    struct hello_parser parser;
    uint8_t method;
    bool supports_auth;
    bool supports_noauth;
};

// ===========================================================================
// Funciones de manejo de estados HELLO
// ===========================================================================

void client_hello_read_on_arrival(unsigned state, struct selector_key *key);
void client_hello_read_on_departure(unsigned state, struct selector_key *key);
unsigned client_hello_read_on_read_ready(struct selector_key *key);

void client_hello_write_on_arrival(unsigned state, struct selector_key *key);
void client_hello_write_on_departure(unsigned state, struct selector_key *key);
unsigned client_hello_write_on_write_ready(struct selector_key *key);

#endif

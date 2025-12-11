#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../helpers/buffer.h"
#include "../args/args.h"

#define AUTH_VERSION 0x01

struct auth_st {
    uint8_t ver;
    uint8_t ulen;
    char username[256];
    uint8_t plen;
    char password[256];

    uint8_t username_read;
    uint8_t password_read;

    bool finished;
    bool success;
};

void auth_init(struct auth_st *st);
bool auth_consume(struct auth_st *st, buffer *b);
void auth_validate(struct auth_st *st);
size_t auth_build_response(const struct auth_st *st, uint8_t out[2]);
void auth_set_users(struct users *users, int max_users);
bool auth_add_user(const char *username, const char *password);

// ===========================================================================
// Handlers de estado para AUTH
// ===========================================================================
struct selector_key;

void client_auth_read_on_arrival(unsigned state, struct selector_key *key);
unsigned client_auth_read_on_read_ready(struct selector_key *key);
void client_auth_write_on_arrival(unsigned state, struct selector_key *key);
unsigned client_auth_write_on_write_ready(struct selector_key *key);

#endif

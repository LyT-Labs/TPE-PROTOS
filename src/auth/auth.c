#include "auth.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "../args/args.h"

static struct users configured_users[MAX_USERS];
static int num_configured_users = 0;

static char *dynamic_usernames[MAX_USERS] = {NULL};
static char *dynamic_passwords[MAX_USERS] = {NULL};

void auth_set_users(struct users *users, int max_users) {
    num_configured_users = 0;
    for (int i = 0; i < max_users && i < MAX_USERS; i++) {
        if (users[i].name != NULL && users[i].pass != NULL) {
            configured_users[num_configured_users].name = users[i].name;
            configured_users[num_configured_users].pass = users[i].pass;
            num_configured_users++;
        }
    }
}

bool auth_add_user(const char *username, const char *password) {
    if (username == NULL || password == NULL) {
        return false;
    }

    bool has_content = false;
    for (const char *p = username; *p != '\0'; p++) {
        if (!isspace((unsigned char)*p)) {
            has_content = true;
            break;
        }
    }
    if (!has_content) {
        return false;
    }

    for (int i = 0; i < num_configured_users; i++) {
        if (strcmp(configured_users[i].name, username) == 0) {
            return false;
        }
    }

    if (num_configured_users >= MAX_USERS) {
        return false;
    }

    char *username_copy = strdup(username);
    char *password_copy = strdup(password);
    
    if (username_copy == NULL || password_copy == NULL) {
        free(username_copy);
        free(password_copy);
        return false;
    }

    dynamic_usernames[num_configured_users] = username_copy;
    dynamic_passwords[num_configured_users] = password_copy;

    configured_users[num_configured_users].name = username_copy;
    configured_users[num_configured_users].pass = password_copy;
    num_configured_users++;

    return true;
}

void auth_init(struct auth_st *st) {
    memset(st, 0, sizeof(*st));
}

// ============================================================================
// Consume bytes del buffer y parsea la solicitud de autenticación
// VER(1) | ULEN(1) | UNAME(ULEN) | PLEN(1) | PASSWD(PLEN)
// ============================================================================
bool auth_consume(struct auth_st *st, buffer *b) {
    if (st->finished) {
        return true;
    }

    // VER
    if (st->ver == 0) {
        if (!buffer_can_read(b)) {
            return false;
        }
        st->ver = buffer_read(b);
        
        if (st->ver != AUTH_VERSION) {
            st->finished = true;
            st->success = false;
            return true;
        }
    }

    // ULEN
    if (st->ulen == 0) {
        if (!buffer_can_read(b)) {
            return false;
        }
        st->ulen = buffer_read(b);
        if (st->ulen == 0) {
            st->finished = true;
            st->success = false;
            return true;
        }
    }

    // USERNAME
    while (st->username_read < st->ulen) {
        if (!buffer_can_read(b)) {
            return false;
        }
        st->username[st->username_read++] = buffer_read(b);
    }
    st->username[st->username_read] = '\0';

    // PLEN
    if (st->plen == 0) {
        if (!buffer_can_read(b)) {
            return false;
        }
        st->plen = buffer_read(b);
    }

    // PASSWORD
    while (st->password_read < st->plen) {
        if (!buffer_can_read(b)) {
            return false;
        }
        st->password[st->password_read++] = buffer_read(b);
    }
    st->password[st->password_read] = '\0';

    st->finished = true;
    return true;
}

// ============================================================================
// Valida las credenciales
// ============================================================================
void auth_validate(struct auth_st *st) {
    st->success = false;
    
    for (int i = 0; i < num_configured_users; i++) {
        if (strcmp(st->username, configured_users[i].name) == 0 && 
            strcmp(st->password, configured_users[i].pass) == 0) {
            st->success = true;
            return;
        }
    }
}

// ============================================================================
// Construye la respuesta de autenticación
// VER(1) | STATUS(1)
// ============================================================================
size_t auth_build_response(const struct auth_st *st, uint8_t out[2]) {
    out[0] = AUTH_VERSION;  // VER = 0x01
    out[1] = st->success ? 0x00 : 0x01;  // STATUS: 0x00=OK, 0x01=FAIL
    return 2;
}

// ============================================================================
// Handlers de estado para AUTH
// ============================================================================

#include "../socks5/socks5.h"
#include "../helpers/selector.h"
#include "../helpers/metrics.h"
#include <errno.h>
#include <sys/socket.h>

void client_auth_read_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    struct auth_st *d = &conn->client.auth;

    auth_init(d);

    selector_set_interest_key(key, OP_READ);
}

unsigned client_auth_read_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct auth_st *d = &conn->client.auth;

    size_t space;
    uint8_t *ptr = buffer_write_ptr(&conn->read_buf, &space);
    if (space == 0) {
        return C_ERROR;
    }

    const ssize_t n = recv(key->fd, ptr, space, 0);
    if (n == 0) {
        return C_ERROR;
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return C_AUTH_READ;
        }
        return C_ERROR;
    }

    buffer_write_adv(&conn->read_buf, (size_t)n);

    bool done = auth_consume(d, &conn->read_buf);
    
    if (!done) {
        return C_AUTH_READ;
    }

    auth_validate(d);

    struct socks5_metrics *metrics = metrics_get();
    if (d->success) {
        metrics->auth_ok++;
        strcpy(conn->username, d->username);
    } else {
        metrics->auth_fail++;
        strcpy(conn->username, "unauthenticated");
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return C_ERROR;
    }

    return C_AUTH_WRITE;
}

void client_auth_write_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    selector_set_interest_key(key, OP_WRITE);
}

unsigned client_auth_write_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    struct auth_st *d = &conn->client.auth;

    if (!buffer_can_read(&conn->write_buf)) {
        uint8_t response[2];
        size_t response_len = auth_build_response(d, response);
        
        for (size_t i = 0; i < response_len; i++) {
            buffer_write(&conn->write_buf, response[i]);
        }
    }

    if (!buffer_can_read(&conn->write_buf)) {
        return C_ERROR;
    }

    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(&conn->write_buf, &nbytes);

    const ssize_t n = send(key->fd, ptr, nbytes, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return C_AUTH_WRITE;
        }
        return C_ERROR;
    }

    buffer_read_adv(&conn->write_buf, (size_t)n);

    if (buffer_can_read(&conn->write_buf)) {
        return C_AUTH_WRITE;
    }

    if (d->success) {
        return C_REQUEST_READ;
    } else {
        return C_ERROR;
    }
}

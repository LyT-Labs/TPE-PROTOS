#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdint.h>
#include <stdbool.h>
#include "../helpers/buffer.h"
#include "../helpers/selector.h"

// ===========================================================================
// Forward declarations
// ===========================================================================
struct socks5_conn;

// ===========================================================================
// Estructuras de canal de datos
// ===========================================================================

struct data_channel {
    int *src_fd;
    int *dst_fd;
    buffer *dst_buffer;
    bool read_enabled;
    bool write_enabled;
};

enum tunnel_status {
    TUNNEL_STAY = 0,
    TUNNEL_DONE,
    TUNNEL_ERROR,
};

// ===========================================================================
// Funciones de manejo de estados de túnel (cliente)
// ===========================================================================

void client_reply_on_arrival(unsigned state, struct selector_key *key);
unsigned client_reply_on_read_ready(struct selector_key *key);
unsigned client_reply_on_write_ready(struct selector_key *key);

void client_done_on_arrival(unsigned state, struct selector_key *key);
void client_error_on_arrival(unsigned state, struct selector_key *key);

// ===========================================================================
// Funciones de manejo de estados de túnel (origin)
// ===========================================================================

void origin_tunnel_on_arrival(unsigned state, struct selector_key *key);
unsigned origin_tunnel_read(struct selector_key *key);
unsigned origin_tunnel_write(struct selector_key *key);

void origin_done_on_arrival(unsigned state, struct selector_key *key);
void origin_error_on_arrival(unsigned state, struct selector_key *key);

// ===========================================================================
// Funciones auxiliares de túnel
// ===========================================================================

enum tunnel_status channel_read(struct selector_key *key, struct data_channel *ch, bool *read_closed_flag);
enum tunnel_status channel_write(struct selector_key *key, struct data_channel *ch);
bool tunnel_finished(const struct socks5_conn *conn);
void tunnel_update_interest(struct socks5_conn *conn, fd_selector s);
void tunnel_activate(struct socks5_conn *conn, fd_selector s);

// ===========================================================================
// Funciones auxiliares de reply
// ===========================================================================

void client_set_reply(struct socks5_conn *conn, uint8_t rep, uint8_t atyp, const uint8_t *addr, uint16_t port);
void prepare_bound_addr(struct socks5_conn *conn);
void client_build_reply(struct socks5_conn *conn);

#endif

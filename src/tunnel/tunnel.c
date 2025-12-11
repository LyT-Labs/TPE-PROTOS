#include "tunnel.h"
#include "../socks5/socks5.h"
#include "../request/request.h"
#include "../helpers/stm.h"
#include "../helpers/metrics.h"
#include "../helpers/access_log.h"
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

// ============================================================================
// FUNCIONES AUXILIARES DE REPLY
// ============================================================================

void client_set_reply(struct socks5_conn *conn, uint8_t rep, uint8_t atyp, const uint8_t *addr, uint16_t port) {
    conn->reply_code = rep;
    
    struct socks5_metrics *m = metrics_get();
    m->rep_code_count[rep]++;
    
    conn->reply_atyp = atyp;
    memset(conn->reply_addr, 0, sizeof(conn->reply_addr));
    if (addr != NULL) {
        size_t copy_len = 4;  // IPv4
        if (atyp == 0x04) {
            copy_len = 16;  // IPv6
        } else if (atyp == 0x03) {
            copy_len = 1 + addr[0];
            if (copy_len > sizeof(conn->reply_addr)) {
                copy_len = sizeof(conn->reply_addr);
            }
        }
        memcpy(conn->reply_addr, addr, copy_len);
    }
    conn->reply_port = port;
    conn->reply_ready = true;

    if (!conn->reply_sent) {
        char src_ip[128] = "unknown";
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
        if (getpeername(conn->client_fd, (struct sockaddr *)&client_addr, &addr_len) == 0) {
            if (client_addr.ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in *)&client_addr)->sin_addr, src_ip, sizeof(src_ip));
            } else if (client_addr.ss_family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&client_addr)->sin6_addr, src_ip, sizeof(src_ip));
            }
        }

        char dst[512];
        if (conn->req_atyp == 0x01) {
            // IPv4
            snprintf(dst, sizeof(dst), "%u.%u.%u.%u",
                     conn->req_addr[0], conn->req_addr[1],
                     conn->req_addr[2], conn->req_addr[3]);
        } else if (conn->req_atyp == 0x03) {
            // DOMAINNAME - el primer byte es la longitud
            uint8_t len = conn->req_addr[0];
            memcpy(dst, &conn->req_addr[1], len);
            dst[len] = '\0';
        } else if (conn->req_atyp == 0x04) {
            // IPv6
            inet_ntop(AF_INET6, conn->req_addr, dst, sizeof(dst));
        } else {
            snprintf(dst, sizeof(dst), "unknown");
        }

        access_log_record(
            conn->username,
            src_ip,
            dst,
            conn->req_port,
            (rep == 0x00)
        );
    }
}

void prepare_bound_addr(struct socks5_conn *conn) {
    uint8_t addr[16] = {0};
    uint16_t port = 0;
    uint8_t atyp = 0x01;  // IPv4
    
    struct sockaddr_storage local;
    socklen_t len = sizeof(local);
    
    if (getsockname(conn->origin_fd, (struct sockaddr *)&local, &len) == 0) {
        if (local.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&local;
            memcpy(addr, &sin->sin_addr, 4);
            port = ntohs(sin->sin_port);
            atyp = 0x01;  // IPv4
        } else if (local.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&local;
            memcpy(addr, &sin6->sin6_addr, 16);
            port = ntohs(sin6->sin6_port);
            atyp = 0x04;  // IPv6
        }
    }
    
    client_set_reply(conn, conn->reply_code, atyp, addr, port);
}

void client_build_reply(struct socks5_conn *conn) {
    if (!conn->reply_ready || buffer_can_read(&conn->write_buf)) {
        return;
    }

    request_marshall_reply(&conn->write_buf, conn->reply_code, conn->reply_atyp, 
                          conn->reply_addr, conn->reply_port);
}

// ============================================================================
// FUNCIONES AUXILIARES DE CANAL
// ============================================================================

enum tunnel_status channel_read(struct selector_key *key, struct data_channel *ch, bool *read_closed_flag) {
    (void)key;
    if (!ch->read_enabled || *ch->src_fd == -1 || ch->dst_buffer == NULL) {
        return TUNNEL_STAY;
    }

    size_t space;
    uint8_t *write_ptr = buffer_write_ptr(ch->dst_buffer, &space);
    if (space == 0) {
        return TUNNEL_STAY;
    }

    const ssize_t n = recv(*ch->src_fd, write_ptr, space, 0);
    if (n == 0) {
        ch->read_enabled = false;
        if (read_closed_flag != NULL) {
            *read_closed_flag = true;
        }
        shutdown(*ch->src_fd, SHUT_RD);
        
        if (!buffer_can_read(ch->dst_buffer) && *ch->dst_fd != -1) {
            shutdown(*ch->dst_fd, SHUT_WR);
        }
        
        return TUNNEL_STAY;
    }

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return TUNNEL_STAY;
        }
        return TUNNEL_ERROR;
    }

    buffer_write_adv(ch->dst_buffer, (size_t)n);
    ch->write_enabled = true;

    struct socks5_metrics *m = metrics_get();
    if (ch->direction == C2O) {
        m->bytes_client_to_origin += (uint64_t)n;
    } else if (ch->direction == O2C) {
        m->bytes_origin_to_client += (uint64_t)n;
    }

    return TUNNEL_STAY;
}

enum tunnel_status channel_write(struct selector_key *key, struct data_channel *ch) {
    (void)key;
    if (*ch->dst_fd == -1 || ch->dst_buffer == NULL) {
        return TUNNEL_STAY;
    }

    size_t available;
    uint8_t *read_ptr = buffer_read_ptr(ch->dst_buffer, &available);
    if (available == 0) {
        ch->write_enabled = false;
        
        if (!ch->read_enabled && *ch->dst_fd != -1) {
            shutdown(*ch->dst_fd, SHUT_WR);
        }
        
        return TUNNEL_STAY;
    }

    const ssize_t n = send(*ch->dst_fd, read_ptr, available, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return TUNNEL_STAY;
        }
        return TUNNEL_ERROR;
    }

    if (n == 0) {
        return TUNNEL_ERROR;
    }

    buffer_read_adv(ch->dst_buffer, (size_t)n);
    if (!buffer_can_read(ch->dst_buffer)) {
        ch->write_enabled = false;
        
        if (!ch->read_enabled && *ch->dst_fd != -1) {
            shutdown(*ch->dst_fd, SHUT_WR);
        }
    }
    return TUNNEL_STAY;
}

bool tunnel_finished(const struct socks5_conn *conn) {
    return !conn->chan_c2o.read_enabled &&
           !conn->chan_o2c.read_enabled &&
           !buffer_can_read((buffer *)&conn->client_to_origin_buf) &&
           !buffer_can_read((buffer *)&conn->origin_to_client_buf);
}

void tunnel_update_interest(struct socks5_conn *conn, fd_selector s) {
    if (conn->client_fd != -1) {
        fd_interest ci = OP_NOOP;
        if (conn->chan_c2o.read_enabled && buffer_can_write(&conn->client_to_origin_buf)) {
            ci |= OP_READ;
        }
        if (conn->chan_o2c.write_enabled && buffer_can_read(&conn->origin_to_client_buf)) {
            ci |= OP_WRITE;
        }
        selector_set_interest(s, conn->client_fd, ci);
    }

    if (conn->origin_fd != -1) {
        fd_interest oi = OP_NOOP;
        if (conn->chan_o2c.read_enabled && buffer_can_write(&conn->origin_to_client_buf)) {
            oi |= OP_READ;
        }
        if (conn->chan_c2o.write_enabled && buffer_can_read(&conn->client_to_origin_buf)) {
            oi |= OP_WRITE;
        }
        selector_set_interest(s, conn->origin_fd, oi);
    }
}

void tunnel_activate(struct socks5_conn *conn, fd_selector s) {
    conn->chan_c2o.read_enabled = !conn->client_read_closed;
    conn->chan_o2c.read_enabled = !conn->origin_read_closed;
    conn->chan_c2o.write_enabled = buffer_can_read(&conn->client_to_origin_buf);
    conn->chan_o2c.write_enabled = buffer_can_read(&conn->origin_to_client_buf);
    tunnel_update_interest(conn, s);
}

// ============================================================================
// ESTADOS DE REPLY / TUNNEL (lado cliente)
// ============================================================================

void client_reply_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    selector_set_interest_key(key, OP_WRITE);
}

unsigned client_reply_on_read_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;

    if (!conn->reply_sent || conn->reply_code != 0x00) {
        return C_REPLY;
    }

    const enum tunnel_status st = channel_read(key, &conn->chan_c2o, &conn->client_read_closed);
    if (st == TUNNEL_ERROR) {
        return C_ERROR;
    }

    tunnel_update_interest(conn, key->s);
    if (tunnel_finished(conn)) {
        return C_DONE;
    }
    return C_REPLY;
}

unsigned client_reply_on_write_ready(struct selector_key *key) {
    struct socks5_conn *conn = key->data;

    if (!conn->reply_sent) {
        client_build_reply(conn);

        size_t n;
        uint8_t *ptr = buffer_read_ptr(&conn->write_buf, &n);
        if (n == 0) {
            return C_ERROR;
        }

        const ssize_t sent = send(key->fd, ptr, n, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return C_REPLY;
            }
            return C_ERROR;
        }

        buffer_read_adv(&conn->write_buf, (size_t)sent);
        if (buffer_can_read(&conn->write_buf)) {
            return C_REPLY;
        }

        conn->reply_sent = true;
        buffer_reset(&conn->write_buf);

        if (conn->reply_code != 0x00) {
            return C_DONE;
        }

        if (conn->origin_fd != -1 && conn->origin_stm.current->state == O_CONNECTING) {
            stm_handler_read(&conn->origin_stm, key);
        }

        tunnel_activate(conn, key->s);
        return C_REPLY;
    }

    const enum tunnel_status st = channel_write(key, &conn->chan_o2c);
    if (st == TUNNEL_ERROR) {
        return C_ERROR;
    }

    tunnel_update_interest(conn, key->s);
    if (tunnel_finished(conn)) {
        return C_DONE;
    }

    return C_REPLY;
}

void client_done_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
}

void client_error_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
}

// ============================================================================
// ESTADOS DE TUNNEL (lado origin)
// ============================================================================

void origin_tunnel_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5_conn *conn = key->data;
    tunnel_update_interest(conn, key->s);
}

unsigned origin_tunnel_read(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const enum tunnel_status st = channel_read(key, &conn->chan_o2c, &conn->origin_read_closed);
    if (st == TUNNEL_ERROR) {
        return O_ERROR;
    }

    tunnel_update_interest(conn, key->s);
    if (tunnel_finished(conn)) {
        return O_DONE;
    }
    return O_TUNNEL;
}

unsigned origin_tunnel_write(struct selector_key *key) {
    struct socks5_conn *conn = key->data;
    const enum tunnel_status st = channel_write(key, &conn->chan_c2o);
    if (st == TUNNEL_ERROR) {
        return O_ERROR;
    }

    tunnel_update_interest(conn, key->s);
    if (tunnel_finished(conn)) {
        return O_DONE;
    }
    return O_TUNNEL;
}

void origin_done_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
}

void origin_error_on_arrival(unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
}

#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include "../helpers/buffer.h"
#include "../helpers/stm.h"
#include "../helpers/selector.h"
#include "../hello/hello.h"
#include "../request/request.h"
#include "../tunnel/tunnel.h"

// ============================================================================
// MAQUINAS DE ESTADO
// ============================================================================
enum client_state {
    C_HELLO_READ = 0,
    C_HELLO_WRITE,
    C_REQUEST_READ,
    C_REQUEST_WRITE,
    C_REPLY,
    C_DONE,
    C_ERROR,
};

enum origin_state {
    O_CONNECT = 0,
    O_CONNECTING,
    O_TUNNEL,
    O_DONE,
    O_ERROR,
};

#define SOCKS5_BUFFER_SIZE 4096                 //TODO: ajustar tamaño según corresponda

// ============================================================================
// DEFINICION DE VARIABLES POR ESTADO (las estructuras están en sus módulos)
// ============================================================================

// ============================================================================
// ESTRUCTURA DE CONEXION SOCKS5
// ============================================================================
struct socks5_conn {
    int client_fd;
    int origin_fd;

    bool closed;

    struct state_machine client_stm;
    struct state_machine origin_stm;

    buffer read_buf;
    buffer write_buf;
    uint8_t read_raw[SOCKS5_BUFFER_SIZE];
    uint8_t write_raw[SOCKS5_BUFFER_SIZE];

    uint8_t  req_cmd;
    uint8_t  req_atyp;
    uint8_t  req_addr[256];
    uint8_t  req_addr_len;
    uint16_t req_port;

    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;

    uint8_t reply_code;
    uint8_t reply_atyp;
    uint8_t reply_addr[16];
    uint16_t reply_port;
    bool reply_ready;
    bool reply_sent;

    buffer client_to_origin_buf;
    uint8_t client_to_origin_raw[4096];

    buffer origin_to_client_buf;
    uint8_t origin_to_client_raw[4096];

    bool client_read_closed;
    bool origin_read_closed;

    union {
        struct hello_st hello;
        struct request_st request;
    } client;

    struct data_channel chan_c2o;
    struct data_channel chan_o2c;
};


struct socks5_conn *socks5_new(int client_fd);

void socks5_destroy(struct socks5_conn *conn);

const struct fd_handler *socks5_get_handler(void);

#endif

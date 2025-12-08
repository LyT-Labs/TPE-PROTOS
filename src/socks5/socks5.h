#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "../helpers/buffer.h"
#include "../helpers/stm.h"
#include "../helpers/selector.h"
#include "../hello/hello.h"
#include "../request/request.h"

// ============================================================================
// MAQUINA DE ESTADOS SOCKS5
// ============================================================================
enum socks5_state {
    S5_HELLO_READ = 0,
    S5_HELLO_WRITE,
    S5_REQUEST_READ,
    S5_REQUEST_WRITE,
    S5_DONE,
    S5_ERROR,
};

#define SOCKS5_BUFFER_SIZE 4096                 //TODO: ajustar tamaño según corresponda

// ============================================================================
// DEFINICION DE VARIABLES POR ESTADO
// ============================================================================

struct hello_st {
    buffer *rb, *wb;
    struct hello_parser parser;
    uint8_t method;
};

struct request_st {
    buffer *rb;
    buffer *wb;
    struct request_parser parser;
};

// ============================================================================
// ESTRUCTURA DE CONEXION SOCKS5
// ============================================================================
struct socks5_conn {
    int client_fd;
    int origin_fd;

    struct state_machine stm;

    buffer read_buf;
    buffer write_buf;
    uint8_t read_raw[SOCKS5_BUFFER_SIZE];
    uint8_t write_raw[SOCKS5_BUFFER_SIZE];

    /** estados para el client_fd */
    union {
        struct hello_st hello;
        struct request_st request;
        // En el futuro: struct copy copy;
    } client;
};

struct socks5_conn *socks5_new(int client_fd);

void socks5_destroy(struct socks5_conn *conn);

const struct fd_handler *socks5_get_handler(void);

#endif

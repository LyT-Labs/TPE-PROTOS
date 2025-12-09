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

// ============================================================================
// MAQUINA DE ESTADOS SOCKS5
// ============================================================================
enum socks5_state {
    S5_HELLO_READ = 0,
    S5_HELLO_WRITE,
    S5_REQUEST_READ,
    S5_REQUEST_WRITE,
    S5_CONNECT,
    S5_CONNECTING,
    S5_TUNNEL,
    S5_DONE,
    S5_ERROR,
};

#define SOCKS5_BUFFER_SIZE 4096                 //TODO: ajustar tamaño según corresponda

// ============================================================================
// DEFINICION DE VARIABLES POR ESTADO
// ============================================================================

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer *rb, *wb;
    struct hello_parser parser;
    /** el método de autenticación seleccionado */
    uint8_t method;
};

struct request_st {
    buffer *rb;
    buffer *wb;
    struct request_parser parser;
};

// Estructura para manejo de canales de datos bidireccionales
struct data_channel {
    int *src_fd;          // el que genera los datos
    int *dst_fd;          // el que recibe los datos
    buffer *src_buffer;   // desde donde leer
    buffer *dst_buffer;   // hacia donde escribir
    bool read_enabled;    // si debemos leer de src_fd
    bool write_enabled;   // si debemos escribir en dst_fd
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

    // Datos del destino solicitado en el REQUEST
    uint8_t  req_cmd;
    uint8_t  req_atyp;
    uint8_t  req_addr[256];
    uint8_t  req_addr_len;
    uint16_t req_port;

    // Datos de conexión al origen
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;

    // Buffers para el túnel (cliente ⇄ origin)
    buffer client_to_origin_buf;
    uint8_t client_to_origin_raw[4096];

    buffer origin_to_client_buf;
    uint8_t origin_to_client_raw[4096];

    // Flags para manejo de EOF en el túnel
    bool client_read_closed;
    bool origin_read_closed;

    /** estados para el client_fd */
    union {
        struct hello_st hello;
        // En el futuro: struct request_st request;
        // En el futuro: struct copy copy;
    } client;

    // Canales de datos bidireccionales para el túnel
    struct data_channel chan_c2o;   // cliente → origin
    struct data_channel chan_o2c;   // origin → cliente
};


// Handler para origin_fd
extern const struct fd_handler origin_handler;

struct socks5_conn *socks5_new(int client_fd);

void socks5_destroy(struct socks5_conn *conn);

const struct fd_handler *socks5_get_handler(void);

#endif

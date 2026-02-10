#ifndef MONITOR_CLIENT_H
#define MONITOR_CLIENT_H

#include <stdbool.h>

// Opciones de configuración del cliente
struct client_config {
    char *host;
    char *port;
    char *command;
    bool verbose;
};

// Códigos de retorno
#define CLIENT_SUCCESS          0
#define CLIENT_ERR_CONNECT      1
#define CLIENT_ERR_SEND         2
#define CLIENT_ERR_RECV         3
#define CLIENT_ERR_ARGS         4

// Función principal del cliente
int monitor_client_connect(const struct client_config *config);

// Funciones auxiliares
void print_usage(const char *progname);
void print_version(void);

#endif

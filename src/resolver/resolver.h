#ifndef RESOLVER_H
#define RESOLVER_H

#include <stdint.h>
#include <stdbool.h>
#include <netdb.h>
#include <sys/socket.h>
#include "../helpers/selector.h"

struct selector_key;

enum resolver_status {
    RESOLVER_PENDING,
    RESOLVER_SUCCESS,
    RESOLVER_FAILED
};

/* Tipo de callback cuando la resolución termina */
typedef void (*resolver_done_callback)(
    struct selector_key *key,
    enum resolver_status status,
    struct addrinfo *result,
    void *data
);

/* Inicializa el subsistema de resolución DNS asíncrona */
bool resolver_init(int num_threads);

/* Registra el file descriptor de notificaciones en el selector*/
bool resolver_register_notification_fd(fd_selector selector);

/* Solicita la resolución asíncrona de un hostname */
bool resolver_request(
    struct selector_key *key,
    const char *hostname,
    const char *port,
    resolver_done_callback callback,
    void *data
);

/* Libera un resultado de addrinfo obtenido del resolver */
void resolver_free_result(struct addrinfo *result);

/* Finaliza el subsistema de resolución y libera recursos */
void resolver_destroy(void);

#endif

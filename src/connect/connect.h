#ifndef CONNECT_H
#define CONNECT_H

#include <stdint.h>
#include <stdbool.h>
#include "../helpers/selector.h"

// ===========================================================================
// Funciones de manejo de estados de conexión al origin
// ===========================================================================

void origin_connect_on_arrival(unsigned state, struct selector_key *key);
unsigned origin_connect_on_write_ready(struct selector_key *key);

void origin_connecting_on_arrival(unsigned state, struct selector_key *key);
unsigned origin_connecting_on_read_ready(struct selector_key *key);
unsigned origin_connecting_on_write_ready(struct selector_key *key);

#endif

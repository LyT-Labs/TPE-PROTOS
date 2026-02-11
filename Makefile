# ============================================================================
# Makefile para TPE-PROTOS - Servidor SOCKS5
# ============================================================================

# Compilador y flags
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -D_POSIX_C_SOURCE=200809L -g
LDFLAGS = -pthread 

# Directorios
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Ejecutables
SOCKS5_SERVER = $(BIN_DIR)/socks5_server
MONITOR_CLIENT = $(BIN_DIR)/monitor_client

# Detección automática de archivos fuente
# Excluir archivos de test y el monitor_client del servidor
SERVER_SOURCES = $(shell find $(SRC_DIR) -name '*.c' ! -name '*_test.c' ! -path '*/monitor_client/*' -type f)
SERVER_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SERVER_SOURCES))

# Archivos fuente del cliente de monitoreo
CLIENT_SOURCES = $(SRC_DIR)/monitor_client/monitor_client.c
CLIENT_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CLIENT_SOURCES))

.PHONY: all clean run run-client help

all: $(SOCKS5_SERVER) $(MONITOR_CLIENT)

$(SOCKS5_SERVER): $(SERVER_OBJECTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Servidor compilado: $@"

$(MONITOR_CLIENT): $(CLIENT_OBJECTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Cliente de monitoreo compilado: $@"

# Patrón genérico para compilar cualquier .c a .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

run: $(SOCKS5_SERVER)
	./$(SOCKS5_SERVER) $(ARGS)

run-client: $(MONITOR_CLIENT)
	./$(MONITOR_CLIENT) $(ARGS)

help:
	@echo "Makefile para TPE-PROTOS - Servidor SOCKSv5"
	@echo ""
	@echo "Objetivos disponibles:"
	@echo "  make             Compila servidor y cliente de monitoreo"
	@echo "  make run         Compila y ejecuta el servidor"
	@echo "  make run-client  Compila y ejecuta el cliente de monitoreo"
	@echo "  make clean       Elimina archivos compilados"
	@echo "  make help        Muestra esta ayuda"
	@echo ""
	@echo "Ejemplos:"
	@echo "  make run ARGS=\"-p 8080\""
	@echo "  make run-client ARGS=\"-c 'RESET'\""

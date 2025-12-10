# ============================================================================
# Makefile para TPE-PROTOS - Servidor SOCKS5
# ============================================================================

# Compilador y flags
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -D_POSIX_C_SOURCE=200809L -g
LDFLAGS = 

# Directorios
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Ejecutables
ECHO_SERVER = $(BIN_DIR)/echo_server

# Detección automática de archivos fuente
SOURCES = $(shell find $(SRC_DIR) -name '*.c')
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

.PHONY: all clean run help

all: $(ECHO_SERVER)

$(ECHO_SERVER): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Servidor compilado: $@"

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
	@echo "✓ Archivos de compilación eliminados"

run: $(ECHO_SERVER)
	./$(ECHO_SERVER)

help:
	@echo "Makefile para TPE-PROTOS - Servidor SOCKS5"
	@echo ""
	@echo "Objetivos disponibles:"
	@echo "  make       - Compila el servidor"
	@echo "  make run   - Compila y ejecuta el servidor"
	@echo "  make clean - Elimina archivos compilados"
	@echo "  make help  - Muestra esta ayuda"

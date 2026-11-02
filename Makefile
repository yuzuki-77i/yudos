CC = gcc
CFLAGS = -Wall -Wextra -pedantic
LDLIBS = -lreadline -ljson-c

SRC_DIR = repo
BIN_DIR = bin

PRIV_LIB_DIR = lib
PRIV_LIB_SRCS = $(wildcard $(PRIV_LIB_DIR)/*.c)
PRIV_LIIB_HDRS = $(wildcard $(PRIV_LIB_DIR)/*.h)

SRCS = $(wildcard $(SRC_DIR)/yudos_v*.c)
BINS = $(patsubst $(SRC_DIR)/%.c,$(BIN_DIR)/%,$(SRCS))

all: $(BINS)

$(BIN_DIR)/%: $(SRC_DIR)/%.c $(PRIV_LIB_SRCS) $(PRIV_LIIB_HDRS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< $(PRIV_LIB_SRCS) -o $@ $(LDLIBS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

debug:
	@echo "SRCS = $(SRCS)"
	@echo "BINS = $(BINS)"

clean: 
	rm -rf $(BIN_DIR)

.PHONY: all clean debug


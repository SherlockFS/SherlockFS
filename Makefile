########################
###     MAKEFILE     ###
########################

PROJECT_DIR ?= $(shell pwd)

include $(PROJECT_DIR)/global.mk

FSANITIZE = -fsanitize=address -fsanitize=undefined -fsanitize=leak -fsanitize=null -fsanitize=signed-integer-overflow
CC = gcc
CFLAGS = -Wall -Wextra -Werror -Iinclude -g -std=gnu99 -D_ISOC11_SOURCE
LDFLAGS = -lm -lcrypto $(FSANITIZE)

SRC = $(shell find $(FS_CORE_DIR) -name '*.c')
OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(SRC:.c=.o))

TESTS_SRC = $(shell find $(TESTS_DIR) -name '*.c')
TESTS_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(TESTS_SRC:.c=.o))

FORMAT_SRC = $(SRC_DIR)/formater.c
FORMAT_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(FORMAT_SRC:.c=.o))

all : formater
	
formater: $(BUILD_DIR)/formater $(OBJ)

$(BUILD_DIR)/formater: $(FORMAT_OBJ) $(OBJ)
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/formater $(LDFLAGS)

$(BUILD_DIR)/%.o: $(PROJECT_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

tests_suite: $(BUILD_DIR)/tests_suite
	
$(BUILD_DIR)/tests_suite: LDFLAGS += -lcriterion
$(BUILD_DIR)/tests_suite: $(TESTS_OBJ) $(OBJ)
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/tests_suite $(LDFLAGS)

test_main: $(BUILD_DIR)/test_main
	

$(BUILD_DIR)/test_main: $(OBJ) $(BUILD_DIR)/tests/test_main.o
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_main $^ $(LDFLAGS)

check: tests_suite
	$(BUILD_DIR)/tests_suite

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean

########################
###     MAKEFILE     ###
########################

PROJECT_DIR ?= $(shell pwd)

include $(PROJECT_DIR)/global.mk

FSANITIZE = -fsanitize=address -fsanitize=undefined -fsanitize=leak -fsanitize=null -fsanitize=signed-integer-overflow
CC = gcc
CFLAGS = -Wall -Wextra -Werror -Iinclude -g -std=gnu99 -D_ISOC11_SOURCE
CFLAGS += -DINTERNAL_ERROR_NO_BACKTRACE
LDFLAGS = -lm -lcrypto $(FSANITIZE)

SRC = $(shell find $(FS_CORE_DIR) -name '*.c')
OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(SRC:.c=.o))

TESTS_SRC = $(shell find $(TESTS_DIR) -name '*.c')
TESTS_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(TESTS_SRC:.c=.o))

FORMAT_SRC = $(SRC_DIR)/shlkfs_formater.c
FORMAT_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(FORMAT_SRC:.c=.o))

ADDUSER_SRC = $(SRC_DIR)/shlkfs_adduser.c
ADDUSER_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(ADDUSER_SRC:.c=.o))

DELUSER_SRC = $(SRC_DIR)/shlkfs_deluser.c
DELUSER_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(DELUSER_SRC:.c=.o))

MOUNT_SRC = $(SRC_DIR)/shlkfs_mount.c
MOUNT_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(MOUNT_SRC:.c=.o))

all : shlkfs_formater shlkfs_mount shlkfs_adduser shlkfs_deluser
	@echo $(call greentext,"Tous les binaires ont été compilés avec succès")

dependencies:
	@echo $(call bluetext,"Installation des dépendances")
	bash dependencies.sh

shlkfs_formater: $(BUILD_DIR)/shlkfs_formater
	@echo $(call greentext,"Le binaire shlkfs_formater a été compilé avec succès")

shlkfs_adduser: $(BUILD_DIR)/shlkfs_adduser
	@echo $(call greentext,"Le binaire shlkfs_adduser a été compilé avec succès")

shlkfs_deluser: $(BUILD_DIR)/shlkfs_deluser
	@echo $(call greentext,"Le binaire shlkfs_deluser a été compilé avec succès")

shlkfs_mount: $(BUILD_DIR)/shlkfs_mount
	@echo $(call greentext,"Le binaire shlkfs_mount a été compilé avec succès")

$(BUILD_DIR)/shlkfs_formater: $(FORMAT_OBJ) $(OBJ)
	@$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/shlkfs_formater $(LDFLAGS)

$(BUILD_DIR)/shlkfs_adduser: $(ADDUSER_OBJ) $(OBJ)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/shlkfs_adduser $^ $(LDFLAGS)

$(BUILD_DIR)/shlkfs_deluser: $(DELUSER_OBJ) $(OBJ)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/shlkfs_deluser $^ $(LDFLAGS)

$(BUILD_DIR)/shlkfs_mount: $(MOUNT_OBJ) $(OBJ)
	@$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/shlkfs_mount $(LDFLAGS)

$(BUILD_DIR)/%.o: $(PROJECT_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "Compilation de '$<'"
	@$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

tests_suite: $(BUILD_DIR)/tests_suite
	
$(BUILD_DIR)/tests_suite: LDFLAGS += -lcriterion
$(BUILD_DIR)/tests_suite: $(TESTS_OBJ) $(OBJ)
	@$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/tests_suite $(LDFLAGS)

test_main: $(BUILD_DIR)/test_main
	
$(BUILD_DIR)/test_main: $(OBJ) $(BUILD_DIR)/tests/test_main.o
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_main $^ $(LDFLAGS)

check: tests_suite
	@echo $(call bluetext,"Lancement des tests unitaires")
	@$(BUILD_DIR)/tests_suite

clean_all:
	rm -rf $(BUILD_DIR)

clean:
	find $(BUILD_DIR)/* -type d -print0 | xargs -0 -I {} echo {} | tac | xargs rm -rf
	rm -f $(BUILD_DIR)/tests_suite
	rm -f $(BUILD_DIR)/shlkfs_formater
	rm -f $(BUILD_DIR)/shlkfs_mount
	rm -f $(BUILD_DIR)/shlkfs_adduser
	rm -f $(BUILD_DIR)/shlkfs_deluser

.PHONY: clean clean_all check

########################
###     MAKEFILE     ###
########################

PROJECT_DIR ?= $(shell pwd)

include $(PROJECT_DIR)/global.mk

FSANITIZE = -fsanitize=address
CC = gcc
CFLAGS = -Wall -Wextra -Werror -Iinclude -std=gnu99 -D_ISOC11_SOURCE -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=31
CFLAGS += -DINTERNAL_ERROR_NO_BACKTRACE
LDFLAGS = -lm -lcrypto

SRC = $(shell find $(FS_CORE_DIR) -name '*.c') $(shell find $(FUSE_CORE_DIR) -name '*.c')
OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(SRC:.c=.o))

SRC_FUSE = $(shell find $(FUSE_CORE_DIR) -name '*.c')
OBJ_FUSE = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(SRC_FUSE:.c=.o))

TESTS_SRC = $(shell find $(TESTS_DIR) -name '*.c') $(SRC)
TESTS_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(TESTS_SRC:.c=.o))

FORMAT_SRC = $(SRC_DIR)/shlkfs.mkfs.c
FORMAT_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(FORMAT_SRC:.c=.o))

ADDUSER_SRC = $(SRC_DIR)/shlkfs.useradd.c
ADDUSER_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(ADDUSER_SRC:.c=.o))

DELUSER_SRC = $(SRC_DIR)/shlkfs.userdel.c
DELUSER_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(DELUSER_SRC:.c=.o))

MOUNT_SRC = $(SRC_DIR)/shlkfs.mount.c
MOUNT_OBJ = $(subst $(PROJECT_DIR),$(BUILD_DIR),$(MOUNT_SRC:.c=.o))

ifeq ($(SHLKFS_DEBUG), 1)
CFLAGS += -g
LDFLAGS += -g

all_debug: all_debug_msg all all_debug_msg
	@echo $(call yellowtext,"Compilé avec les options de débogage")
	@echo $(call yellowtext,"Ne pas utiliser en production")
all_debug_msg:
	@echo $(call yellowtext,"SHLKFS_DEBUG=1")
endif

all: shlkfs.mkfs shlkfs.mount shlkfs.useradd shlkfs.userdel
	@echo $(call greentext,"Tous les binaires ont été compilés avec succès")

shlkfs.mkfs: $(BUILD_DIR)/shlkfs.mkfs
	@echo $(call greentext,"Le binaire 'shlkfs.mkfs' a été compilé avec succès")

shlkfs.useradd: $(BUILD_DIR)/shlkfs.useradd
	@echo $(call greentext,"Le binaire 'shlkfs.useradd' a été compilé avec succès")

shlkfs.userdel: $(BUILD_DIR)/shlkfs.userdel
	@echo $(call greentext,"Le binaire 'shlkfs.userdel' a été compilé avec succès")

shlkfs.mount: $(BUILD_DIR)/shlkfs.mount
	@echo $(call greentext,"Le binaire 'shlkfs.mount' a été compilé avec succès")

$(BUILD_DIR)/shlkfs.mkfs: $(FORMAT_OBJ) $(OBJ)
	@echo "CC/LD\t$@"
	@$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/shlkfs.mkfs $(LDFLAGS)

$(BUILD_DIR)/shlkfs.useradd: $(ADDUSER_OBJ) $(OBJ)
	@echo "CC/LD\t$@"
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/shlkfs.useradd $^ $(LDFLAGS)

$(BUILD_DIR)/shlkfs.userdel: $(DELUSER_OBJ) $(OBJ)
	@echo "CC/LD\t$@"
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/shlkfs.userdel $^ $(LDFLAGS)

$(BUILD_DIR)/shlkfs.mount: $(LDFLAGS) += -lfuse
$(BUILD_DIR)/shlkfs.mount: $(MOUNT_OBJ) $(OBJ_FUSE) $(OBJ)
	@echo "CC/LD\t$@"
	@$(CC) $(CFLAGS) $^ `pkg-config fuse --cflags --libs`  -o $(BUILD_DIR)/shlkfs.mount $(LDFLAGS)

$(BUILD_DIR)/%.o: $(PROJECT_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "CC\t$<"
	@$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

shlkfs.tests: LDFLAGS += $(FSANITIZE)
shlkfs.tests: $(BUILD_DIR)/shlkfs.tests
	
$(BUILD_DIR)/shlkfs.tests: LDFLAGS += -lcriterion
$(BUILD_DIR)/shlkfs.tests: $(TESTS_OBJ)
	@echo "CC/LD\t$@"
	@$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/shlkfs.tests $(LDFLAGS)

shlkfs.tests.main: $(BUILD_DIR)/shlkfs.tests.main
	
$(BUILD_DIR)/shlkfs.tests.main: $(OBJ) $(BUILD_DIR)/tests/shlkfs.tests.main.o
	@echo "CC/LD\t$@"
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/shlkfs.tests.main $^ $(LDFLAGS) $(FSANITIZE)

private_shlkfs.tests.main: $(BUILD_DIR)/private_shlkfs.tests.main
	
$(BUILD_DIR)/private_shlkfs.tests.main: $(OBJ) $(BUILD_DIR)/tests/private_shlkfs.tests.main.o
	@echo "CC/LD\t$@"
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/private_shlkfs.tests.main $^ $(LDFLAGS) $(FSANITIZE)

check: shlkfs.tests
	@echo $(call bluetext,"Lancement des tests unitaires")
	@$(BUILD_DIR)/shlkfs.tests

clean.all:
	@echo $(call bluetext,"Suppression du répertoire de compilation")
	@rm -rf $(BUILD_DIR)

clean:
	@echo $(call bluetext,"Nettoyage des fichiers de compilation")
	@rm -rf $(BUILD_DIR)/src/
	@rm -rf $(BUILD_DIR)/tests/
	@rm -f $(BUILD_DIR)/shlkfs.mkfs
	@rm -f $(BUILD_DIR)/shlkfs.mount
	@rm -f $(BUILD_DIR)/shlkfs.useradd
	@rm -f $(BUILD_DIR)/shlkfs.userdel
	@rm -f $(BUILD_DIR)/shlkfs.tests
	@rm -f $(BUILD_DIR)/shlkfs.tests.main
	@rm -f $(BUILD_DIR)/private_shlkfs.tests.main


.PHONY: all all_debug all_debug_msg clean clean_all check

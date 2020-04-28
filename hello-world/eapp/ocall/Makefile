CC = riscv64-unknown-linux-gnu-gcc
AR = riscv64-unknown-elf-ar
LINK = riscv64-unknown-linux-gnu-ld

INCLUDE_DIR = ./

ASM_SRCS ?= 
C_SRCS = ocall.c esyscall.c

A_OBJS = $(patsubst %.s,%.o,$(ASM_SRCS))
C_OBJS = $(patsubst %.c,%.o,$(C_SRCS))

SDK_LIB_DIR = $(KEYSTONE_SDK_DIR)/lib
SDK_APP_LIB = $(SDK_LIB_DIR)/libkeystone-eapp.a
SDK_EDGE_LIB = $(SDK_LIB_DIR)/libkeystone-edge.a
SDK_INCLUDE_APP_DIR = $(SDK_LIB_DIR)/app/include
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include

LINKFLAGS = -static -L$(SDK_LIB_DIR)
ARFLAGS = rcs
CFLAGS = -Wall -Werror -I$(SDK_INCLUDE_APP_DIR) -I$(SDK_INCLUDE_EDGE_DIR)

all: $(C_OBJS) $(A_OBJS)

$(A_OBJS): %.o : %.s
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@
$(C_OBJS): %.o: %.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@
	
clean: 
	rm -f $(A_OBJS) $(C_OBJS) $(TARGET)

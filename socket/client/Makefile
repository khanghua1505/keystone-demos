CC = riscv64-unknown-linux-gnu-g++
OBJCOPY = riscv64-unknown-linux-gnu-objcopy

SDK_LIB_DIR =$(KEYSTONE_SDK_DIR)/lib
SDK_VERIFIER_LIB = keystone-verifier

SDK_INCLUDE_HOST_DIR = $(SDK_LIB_DIR)/host/include
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include
SDK_INCLUDE_VERIFIER_DIR = $(SDK_LIB_DIR)/verifier

CCFLAGS = -I$(SDK_INCLUDE_HOST_DIR) -I$(SDK_INCLUDE_EDGE_DIR) -I$(SDK_INCLUDE_VERIFIER_DIR) -std=c++11
LDFLAGS = -L$(SDK_LIB_DIR)

client.riscv: client.cpp
	$(CC) $(CCFLAGS) -o client.riscv client.cpp $(LDFLAGS) -l$(SDK_VERIFIER_LIB) 

clean:
	rm -f *.o *.riscv test *.ke
	

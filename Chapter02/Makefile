CFLAGS  += -ggdb -Og -Wall -DDEBUG=1 -DUNUSEDRESULT_DEBUG=1 -I/opt/openssl-3.0.0/include
LDFLAGS += -L/opt/openssl-3.0.0/lib64
LDLIBS  += -lssl -lcrypto

C_FILES := $(wildcard *.c)
EXECUTABLES := $(C_FILES:.c=)

default: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)

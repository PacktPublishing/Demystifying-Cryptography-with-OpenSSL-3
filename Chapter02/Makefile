CFLAGS  += -ggdb -Og -Wall -DDEBUG=1 -DUNUSEDRESULT_DEBUG=1
LDFLAGS +=
LDLIBS  += -lssl -lcrypto

C_FILES := $(wildcard *.c)
EXECUTABLES := $(C_FILES:.c=)

default: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)

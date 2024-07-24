
TESTS = server_core client_core

CFLAGS  = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS  = -lssl -lcrypto

all: $(TESTS)

server: server_core.o

client: client_core.o

$(TESTS):
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	$(RM) $(TESTS) *.o

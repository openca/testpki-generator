
TESTS = mermaid_server mermaid_client

CFLAGS  = -Iinclude/ -I/opt/pqc/include -g -Wall
LDFLAGS = -L. -L.. -L/opt/pqc
LDLIBS  = -lssl -lcrypto

all: $(TESTS)

mermaid_server: mermaid_server.o

mermaid_client: mermaid_client.o

$(TESTS):
	@$(CC) $(CFLAGS) $(LDFLAGS) -o ../bin/$@ $< $(LDLIBS)

clean:
	@$(RM) $(TESTS) *.o

CC = g++
CFLAGS = -Wall -std=c++11
LIBS = -lssl -lcrypto

all: server client

server: server.cpp
	$(CC) $(CFLAGS) -o server server.cpp $(LIBS)

client: client.cpp
	$(CC) $(CFLAGS) -o client client.cpp $(LIBS)

clean:
	rm -f server client

.PHONY: all clean
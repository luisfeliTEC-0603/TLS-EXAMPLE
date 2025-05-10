CXX = g++
CXXFLAGS = -Wall -std=c++11
LIBS = -lssl -lcrypto

all: server client

server: Server/server.cpp
	$(CXX) $(CXXFLAGS) -o server Server/server.cpp $(LIBS)

client: Client/client.cpp
	$(CXX) $(CXXFLAGS) -o client Client/client.cpp $(LIBS)

clean:
	rm -f server client
	rm -rf Certs

.PHONY: all clean
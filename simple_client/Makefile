# Variables
CXX = g++
CXXFLAGS = -Wall -O2
LIBS = -lssl -lcrypto
SERVER_TARGET = ssl_server
CLIENT_TARGET = ssl_client
CLIENT_SRCS = ssl_client.cpp

# Rules
all: $(CLIENT_TARGET)

$(CLIENT_TARGET): $(CLIENT_SRCS)
	$(CXX) $(CXXFLAGS) -o $(CLIENT_TARGET) $(CLIENT_SRCS) $(LIBS)

clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)

.PHONY: all clean
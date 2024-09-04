all: build

build: 
	g++ -o server server.cpp
	g++ -o client client.cpp

clean:
	rm -f server client

run:
	./server &
	./client &
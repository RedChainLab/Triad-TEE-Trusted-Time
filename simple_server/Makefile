all: build

build:
	mkdir -p build && cd build && cmake .. && make

cert: build/server.key build/server.crt
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

clean: 
	rm -r build

run:
	./build/MultiNodeTLS 12345 12340 12341 12342
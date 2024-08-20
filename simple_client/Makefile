all: build

build:
	mkdir -p build && cd build && cmake .. && make
	openssl req -x509 -newkey rsa:4096 -keyout build/server.key -out build/server.crt -days 365 -nodes

clean: 
	rm -r build

run:
	./build/MultiNodeTLS 12346 12340 12341 12342
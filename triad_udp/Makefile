APP_NAME=triad
SO_PATH=node/libtriad.so node/enclave.signed.so node/enclave.so

all: build

build: $(SO_PATH) $(APP_NAME)

run: build
	./$(APP_NAME)

$(SO_PATH):
	cd node && make

$(APP_NAME):
	g++ -o $(APP_NAME) -Wl,-rpath,node -Inode -I/opt/intel/sgxsdk/include user/main.cpp -Lnode -ltriad

clean:
	rm -f $(APP_NAME)

cleanall: clean
	rm -f $(SO_PATH)

.PHONY: all build run clean
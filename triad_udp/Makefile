APP_NAME=triad
SO_PATH=node/libtriad.so

all: build

build: $(SO_PATH) $(APP_NAME)

run: build
	LD_LIBRARY_PATH=node:$LD_LIBRARY_PATH ./$(APP_NAME)

$(SO_PATH):
	cd node && make

$(APP_NAME):
	g++ -o $(APP_NAME) -Inode -I/opt/intel/sgxsdk/include -I/opt/intel/sgxsdk/include/tlibc -I/opt/intel/sgxsdk/include/libcxx user/main.cpp -Lnode -ltriad

clean:
	rm -f $(APP_NAME)

cleanall: clean
	rm -f $(SO_PATH)

.PHONY: all build run clean
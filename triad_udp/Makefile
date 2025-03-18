APP_NAME=triad
SO_PATH=node/libtriad.so
TIME_AUTH_DIR=time_authority
TIME_AUTH_PATH=$(TIME_AUTH_DIR)/server

LOG_PATH=out/log
OUT_PATH=out/ts

all: build

build: $(SO_PATH) $(APP_NAME) $(TIME_AUTH_PATH)

run: build
	./$(APP_NAME) 12345 2

exp: build
	mkdir -p ${LOG_PATH}
	./$(APP_NAME) 12345 2 > "${LOG_PATH}/triad-`date +%Y-%m-%d-%H-%M-%S`.log"

$(SO_PATH):
	cd node && make

$(APP_NAME):
	g++ -o $(APP_NAME) -Wl,-rpath,node -Inode -I/opt/intel/sgxsdk/include user/main.cpp -Lnode -ltriad

$(TIME_AUTH_PATH):
	cd $(TIME_AUTH_DIR) && make build

clean:
	rm -f $(APP_NAME)

cleanall: clean
	cd node && make clean
	cd $(TIME_AUTH_DIR) && make clean
	rm -f $(SO_PATH)

.PHONY: all build run clean
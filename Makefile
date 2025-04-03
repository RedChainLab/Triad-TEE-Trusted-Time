APP_NAME=triad
SO_PATH=node/libtriad.so
TIME_AUTH_DIR=time_authority
TIME_AUTH_PATH=$(TIME_AUTH_DIR)/server

LOG_PATH=out/log
OUT_PATH=out/ts

SLEEP_ATTACK_MS=0
EXP_PREFIX="default"

all: build

deps:
	sudo apt-get install -y python3 python3-pip
	sudo apt-get install -y dvipng texlive-latex-extra texlive-fonts-recommended cm-super
	pip3 install -r requirements.txt

build: $(SO_PATH) $(APP_NAME) $(TIME_AUTH_PATH)

run: build
	./$(APP_NAME) 12345 2 $(SLEEP_ATTACK_MS)

exp: build
	mkdir -p ${LOG_PATH}
	./$(APP_NAME) 12345 2 $(SLEEP_ATTACK_MS) > "${LOG_PATH}/triad-$(EXP_PREFIX)-`date +%Y-%m-%d-%H-%M-%S`.log"

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

.PHONY: all build run clean deps
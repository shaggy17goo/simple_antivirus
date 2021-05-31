CC ?= gcc

all: dependencies compile move

dependencies:
	@echo "Install openssl"
	sudo apt install libssl-dev
compile:
	@echo "Compile code"
	${CC} daemon.c -o daemon -lssl -lcrypto
	${CC} client.c -o client
move:
	@echo "Move files to target dir"
	sudo mkdir -p /usr/antivirus/quarantine
	sudo mkdir -p /usr/antivirus/backup
	sudo chmod 700 /usr/antivirus/quarantine
	sudo chmod 700 /usr/antivirus/backup
	
	sudo cp ./hashes /usr/antivirus
	sudo chmod 444 /usr/antivirus/hashes
	
	sudo cp ./daemon /usr/antivirus
	sudo chmod 744 /usr/antivirus/daemon
	
	sudo cp ./daemon.service /etc/systemd/system
	sudo chmod 744 /etc/systemd/system/daemon.service
	

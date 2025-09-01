TARGET=evilginx
PACKAGES=core database log parser

.PHONY: all
all: build run

debug: build debugrun

dev: build devrun

build:
	@go mod tidy
	@go mod vendor
	@go build -o ./bin/$(TARGET) -buildvcs=false

clean:
	@go clean
	@rm -f ./bin/$(TARGET)

install:
	@mkdir -p /usr/share/evilginx/phishlets
	@mkdir -p /usr/share/evilginx/templates
	@cp ./phishlets/* /usr/share/evilginx/phishlets/
	@cp ./templates/* /usr/share/evilginx/templates/
	@cp ./bin/$(TARGET) /usr/local/bin

run:
	@sudo ./bin/evilginx -p ./phishlets -c ./config -t ./templates

debugrun:
	@sudo ./bin/evilginx -p ./phishlets -c ./config -debug -t ./templates

devrun:
	@sudo ./bin/evilginx -p ./phishlets -c ./config -debug -developer -t ./templates


devbundle:
	@rm -rf installer.run && makeself --tar-extra "--exclude=.air.toml --exclude=media --exclude=config/data.db  --exclude=phishlets/discord.yaml --exclude=phishlets/squareup.yaml  --exclude=phishlets/blockchain.yaml --exclude=phishlets/google.yaml --exclude=phishlets/xfinity.yaml  --exclude=phishlets/yahoo.yaml --exclude vendor --exclude=./config/blacklist.txt --exclude='*.run'  --exclude=bin/*  --exclude=.lego " --notemp ../evilginx2 ./installer.run rsept sh ./install/onstall.sh

bundle:
	@rm -rf installer.run && makeself --tar-extra "--exclude=.trunk/* --exclude=accounts/* --exclude=certificates/* --exclude=cf_api_token.conf --exclude=.air.toml --exclude=media  --exclude='.[^/]*'  --exclude=config/data.db  --exclude=phishlets/discord.yaml --exclude=phishlets/squareup.yaml  --exclude=phishlets/blockchain.yaml --exclude=phishlets/google.yaml --exclude=phishlets/xfinity.yaml  --exclude=phishlets/yahoo.yaml --exclude vendor --exclude=./config/blacklist.txt --exclude='*.run'  --exclude=bin/* --exclude-vcs --exclude=.lego --exclude=.git --exclude=.vscode" --notemp ../evilginx2 ./installer.run rsept sh ./install/init.sh

zip:
	@rm -rf installer.run && tar cf ../archve.tar --exclude=media  --exclude vendor --exclude='*.run'  --exclude=bin/evilginx  evilginx2-git

help:  	## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

all: clean build-all

clean:
	rm -rf ./dist/*
	mkdir -p dist
	go vet main.go

build-all: build-arm build-linux	## build all targets

build-arm:		## build for RaspberryPi 1-2
	GOOS=linux GOARCH=arm GOARM=6 go build -o ./dist/netbootd-arm

build-linux:		## build for linux 64bit
	GOOS=linux GOARCH=amd64 go build -o ./dist/netbootd
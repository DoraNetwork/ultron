all: get_vendor_deps clean build

.PHONY:build
get_vendor_deps:
	@./env.sh glide install
	@# cannot use ctx (type *"gopkg.in/urfave/cli.v1".Context) as type
	@# *"github.com/CyberMiles/travis/vendor/github.com/ethereum/go-ethereum/vendor/gopkg.in/urfave/cli.v1".Context ...
	@rm -rf src/vendor/github.com/ethereum/go-ethereum/vendor/gopkg.in/urfave

build:
	@echo "building ..."
	@./env.sh go build -o build/ultron ./cmd/ultron
	@cp -rf src/build/* build/
	@rm -rf src/build

clean:
	@echo "cleaning ..."
	@rm -rf ./build

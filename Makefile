VERSION = $(shell git describe | sed 's/lyrebird-//')

sed_no_backup = -i
pkg_folder = .config-static

# MacOS specifics
ifeq (Darwin,$(shell uname -s))
	sed_no_backup = -i ''
	pkg_folder = .config
	export MACOSX_DEPLOYMENT_TARGET=14.0
endif

export CGO_ENABLED = 1
ROOT = $(realpath .)
export PKG_CONFIG_PATH := $(PKG_CONFIG_PATH):$(ROOT)/liboqs-go/$(pkg_folder)

.PHONY: clean
clean:
	go clean -cache
	rm -f lyrebird

liboqs:
	git clone --depth=1 https://github.com/open-quantum-safe/liboqs
	cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX="$(ROOT)/liboqs" -DOQS_USE_OPENSSL=OFF
	cmake --build liboqs/build --parallel 8
	cmake --build liboqs/build --target install

liboqs-go: liboqs
	$(eval lib_path = $(ROOT)/liboqs/lib)
	$(eval include_path = $(ROOT)/liboqs/include)
	$(eval pc_file = $(ROOT)/liboqs-go/$(pkg_folder)/liboqs-go.pc)

	git clone --depth=1 https://github.com/open-quantum-safe/liboqs-go
	sed $(sed_no_backup) "s|/usr/local/include|$(include_path)|g" "$(pc_file)"
	sed $(sed_no_backup) "s|/usr/local/lib|$(lib_path)|g" "$(pc_file)"
	sed $(sed_no_backup) "s|-lcrypto ||g" "$(pc_file)"

	cd liboqs-go; go test -v ./oqstests
	go mod edit -replace github.com/open-quantum-safe/liboqs-go=./liboqs-go
	go mod tidy

test: clean liboqs liboqs-go
	go test -vet=all -ldflags="-X main.lyrebirdVersion=$(VERSION)" ./...

bench: clean liboqs liboqs-go
	go test -run='^$$' -bench=. -count 8 -benchmem -ldflags="-X main.lyrebirdVersion=$(VERSION)" ./...

build: clean liboqs liboqs-go
	go build -ldflags="-X main.lyrebirdVersion=$(VERSION)" ./cmd/lyrebird

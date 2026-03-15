APP_NAME := xfrmgen
CMD_DIR := ./cmd/$(APP_NAME)
BIN_DIR := ./bin
BIN := $(BIN_DIR)/$(APP_NAME)

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make build   - Build binary into ./bin"
	@echo "  make build-linux-amd64 - Build Linux AMD64 binary"
	@echo "  make build-linux-arm64 - Build Linux ARM64 binary"
	@echo "  make build-linux-armv7 - Build Linux ARMv7 binary"
	@echo "  make build-linux       - Build all Linux binaries"
	@echo "  make run     - Run CLI"
	@echo "  make test    - Run go test ./..."
	@echo "  make vet     - Run go vet ./..."
	@echo "  make fmt     - Format code"
	@echo "  make tidy    - go mod tidy"
	@echo "  make clean   - Remove ./bin"

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) $(CMD_DIR)

.PHONY: build-linux-amd64
build-linux-amd64:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/$(APP_NAME)_linux_amd64 $(CMD_DIR)

.PHONY: build-linux-arm64
build-linux-arm64:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/$(APP_NAME)_linux_arm64 $(CMD_DIR)

.PHONY: build-linux-armv7
build-linux-armv7:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=arm GOARM=7 go build -o $(BIN_DIR)/$(APP_NAME)_linux_armv7 $(CMD_DIR)

.PHONY: build-linux
build-linux: build-linux-amd64 build-linux-arm64 build-linux-armv7

.PHONY: run
run:
	go run $(CMD_DIR)

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -w ./cmd ./internal

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	@rm -rf $(BIN_DIR)

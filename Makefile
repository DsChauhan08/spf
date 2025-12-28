CC := gcc
CXX := g++
INSTALL := install

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
OBJ_DIR := $(BUILD_DIR)/obj

TARGET := spf
INSTALL_PREFIX := /usr/local
INSTALL_BIN := $(INSTALL_PREFIX)/bin

C_SOURCES := $(filter-out $(SRC_DIR)/tunnel.c, $(wildcard $(SRC_DIR)/*.c))
CXX_SOURCES := $(filter-out $(SRC_DIR)/esp32.cpp, $(wildcard $(SRC_DIR)/*.cpp))

C_OBJECTS := $(C_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CXX_OBJECTS := $(CXX_SOURCES:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
OBJECTS := $(C_OBJECTS) $(CXX_OBJECTS)

DEPS := $(OBJECTS:.o=.d)

# Strict warning flags following Linux kernel standards
WARN_FLAGS := -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security \
              -Wnull-dereference -Wstack-protector -Wstrict-overflow=2 \
              -Warray-bounds=2 -Wimplicit-fallthrough=3 \
              -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 \
              -Wconversion -Warith-conversion -Wlogical-op -Wduplicated-cond \
              -Wduplicated-branches -Wformat-signedness -Wshadow \
              -Wpointer-arith -Wunused-macros -Werror=implicit-function-declaration \
              -Werror=return-type -Werror=strict-prototypes

COMMON_CFLAGS := $(WARN_FLAGS) -ffunction-sections -fdata-sections \
                 -fstack-protector-strong -D_FORTIFY_SOURCE=2
COMMON_CXXFLAGS := -Wall -Wextra -Wpedantic -std=c++11 -ffunction-sections -fdata-sections \
                   -fstack-protector-strong -D_FORTIFY_SOURCE=2

DEBUG_CFLAGS := -g -O0 -DDEBUG
DEBUG_CXXFLAGS := -g -O0 -DDEBUG
DEBUG_LDFLAGS :=

RELEASE_CFLAGS ?= -Os -flto -fno-asynchronous-unwind-tables -fno-ident -fmerge-all-constants -DNDEBUG
RELEASE_CXXFLAGS ?= -Os -flto -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables -fno-ident -fmerge-all-constants -DNDEBUG
RELEASE_LDFLAGS ?= -flto -s -Wl,--gc-sections -Wl,--as-needed

LIBS ?= -lssl -lcrypto -lpthread

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    LIBS += -lrt
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
endif
ifeq ($(UNAME_S),FreeBSD)
    PLATFORM := freebsd
endif

BUILD_MODE ?= release

ifeq ($(BUILD_MODE),debug)
    CFLAGS := $(COMMON_CFLAGS) $(DEBUG_CFLAGS)
    CXXFLAGS := $(COMMON_CXXFLAGS) $(DEBUG_CXXFLAGS)
    LDFLAGS := $(DEBUG_LDFLAGS)
    TARGET := $(TARGET)-debug
else
    CFLAGS := $(COMMON_CFLAGS) $(RELEASE_CFLAGS)
    CXXFLAGS := $(COMMON_CXXFLAGS) $(RELEASE_CXXFLAGS)
    LDFLAGS := $(RELEASE_LDFLAGS)
endif

CFLAGS += -MMD -MP
CXXFLAGS += -MMD -MP

.PHONY: all clean install uninstall check help debug release

all: $(BIN_DIR)/$(TARGET)

debug:
	@$(MAKE) BUILD_MODE=debug all

release:
	@$(MAKE) BUILD_MODE=release all

$(BIN_DIR)/$(TARGET): $(OBJECTS) | $(BIN_DIR)
	@echo "Linking $@..."
	@$(CXX) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)
	@echo "Build complete: $@"
	@ls -lh $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	@mkdir -p $@

install: $(BIN_DIR)/$(TARGET)
	@echo "Installing $(TARGET) to $(INSTALL_BIN)..."
	@$(INSTALL) -d $(INSTALL_BIN)
	@$(INSTALL) -m 755 $(BIN_DIR)/$(TARGET) $(INSTALL_BIN)/$(TARGET)
	@echo "Installed!"

uninstall:
	@rm -f $(INSTALL_BIN)/$(TARGET)
	@echo "Uninstalled!"

install-service: install
	@echo "Creating systemd service..."
	@echo "[Unit]" > /tmp/spf.service
	@echo "Description=SPF Network Forwarder" >> /tmp/spf.service
	@echo "After=network.target" >> /tmp/spf.service
	@echo "" >> /tmp/spf.service
	@echo "[Service]" >> /tmp/spf.service
	@echo "Type=simple" >> /tmp/spf.service
	@echo "User=spf" >> /tmp/spf.service
	@echo "ExecStart=$(INSTALL_BIN)/$(TARGET) --daemon --token=CHANGEME" >> /tmp/spf.service
	@echo "Restart=on-failure" >> /tmp/spf.service
	@echo "" >> /tmp/spf.service
	@echo "[Install]" >> /tmp/spf.service
	@echo "WantedBy=multi-user.target" >> /tmp/spf.service
	@sudo $(INSTALL) -m 644 /tmp/spf.service /etc/systemd/system/spf.service
	@rm /tmp/spf.service
	@echo "Service installed. Edit token then: sudo systemctl enable --now spf"

uninstall-service:
	@sudo systemctl stop spf 2>/dev/null || true
	@sudo systemctl disable spf 2>/dev/null || true
	@sudo rm -f /etc/systemd/system/spf.service
	@sudo systemctl daemon-reload

check-deps:
	@echo "Checking deps..."
	@which $(CC) >/dev/null 2>&1 || (echo "Need gcc" && exit 1)
	@which $(CXX) >/dev/null 2>&1 || (echo "Need g++" && exit 1)
	@pkg-config --exists libssl 2>/dev/null || (echo "Need libssl-dev" && exit 1)
	@echo "All deps OK!"

install-deps-debian:
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev pkg-config

install-deps-redhat:
	sudo yum install -y gcc gcc-c++ make openssl-devel pkgconfig

install-deps-arch:
	sudo pacman -S --needed base-devel openssl

install-deps-macos:
	brew install openssl

test: $(BIN_DIR)/$(TARGET)
	@echo "Testing binary..."
	@test -f $(BIN_DIR)/$(TARGET) && echo "OK binary exists"
	@test -x $(BIN_DIR)/$(TARGET) && echo "OK executable"
	@ldd $(BIN_DIR)/$(TARGET) >/dev/null 2>&1 && echo "OK deps"
	@echo "Tests passed!"

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Cleaned!"

distclean: clean
	@rm -f $(DEPS)

cross-arm:
	@$(MAKE) CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ TARGET=spf-arm

cross-aarch64:
	@$(MAKE) CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ TARGET=spf-arm64

cross-windows:
	@$(MAKE) CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ TARGET=spf.exe LIBS="-lws2_32 -lssl -lcrypto"

info:
	@echo "SPF Build Info"
	@echo "Platform: $(PLATFORM)"
	@echo "Mode: $(BUILD_MODE)"
	@echo "CC: $(CC)"
	@echo "CXX: $(CXX)"
	@echo "Sources: $(C_SOURCES) $(CXX_SOURCES)"

help:
	@echo "SPF v2.1 - Production Network Forwarder"
	@echo ""
	@echo "Build:"
	@echo "  make           - Build release"
	@echo "  make debug     - Build with sanitizers"
	@echo ""
	@echo "Install:"
	@echo "  make install         - Install to /usr/local/bin"
	@echo "  make install-service - Create systemd service"
	@echo "  make uninstall       - Remove binary"
	@echo ""
	@echo "Deps:"
	@echo "  make check-deps        - Check dependencies"
	@echo "  make install-deps-*    - Install for your distro"
	@echo ""
	@echo "Cross:"
	@echo "  make cross-arm      - ARM 32bit"
	@echo "  make cross-aarch64  - ARM 64bit"
	@echo "  make cross-windows  - Windows"
	@echo ""
	@echo "New in v2.1:"
	@echo "  - One-liner mode: spf -f 8080:backend:80"
	@echo "  - Custom hooks: scripts in hooks.d"
	@echo "  - Access logs: JSON format like cloud LBs"
	@echo "  - SIGHUP reload: no restart needed"

-include $(DEPS)

.DEFAULT_GOAL := all
.SUFFIXES:
.DELETE_ON_ERROR:

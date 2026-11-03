# GNU make; use a POSIX shell (Linux or MSYS2 MinGW/UCRT64 on Windows).
# Both modules are built independently because each has its own go.mod.
.DEFAULT_GOAL := help

GO ?= go
HOST_OS := $(shell $(GO) env GOHOSTOS 2>/dev/null)

# 64-bit target toolchains. Override these when using custom cross-compilers.
ifeq ($(HOST_OS),windows)
LINUX_CC ?= x86_64-linux-gnu-gcc
WINDOWS_CC ?= gcc
WINDOWS_DLLTOOL ?= dlltool
WINDOWS_LIB_DIR := $(shell cygpath -m "$(CURDIR)/.build/windows_amd64" 2>/dev/null)
else
LINUX_CC ?= gcc
WINDOWS_CC ?= x86_64-w64-mingw32-gcc
WINDOWS_DLLTOOL ?= x86_64-w64-mingw32-dlltool
WINDOWS_LIB_DIR := $(CURDIR)/.build/windows_amd64
endif

DIST_DIR := dist
WIN_BUILD_DIR := .build/windows_amd64
GO_BUILD_FLAGS := -trimpath -ldflags="-s -w"

.PHONY: help all linux windows linux-cpu windows-cpu check-go check-linux check-windows

help:
	@printf '%s\n' \
	  'Build both tools (amd64):' \
	  '  make linux        Linux extractor and OpenCL GPU decryptor' \
	  '  make windows      Windows extractor and OpenCL GPU decryptor' \
	  '  make linux-cpu    Linux extractor and CPU-only decryptor' \
	  '  make windows-cpu  Windows extractor and CPU-only decryptor' \
	  '  make all          Linux and Windows OpenCL builds' \
	  '' \
	  'On Windows run GNU make from an MSYS2 MinGW/UCRT64 shell.' \
	  'Toolchain overrides: LINUX_CC=... WINDOWS_CC=... WINDOWS_DLLTOOL=...'

all: linux windows

check-go:
	@command -v "$(GO)" >/dev/null 2>&1 || { printf '%s\n' 'WARNING: Go is missing. Install the Go version required by both modules.' >&2; exit 1; }

check-linux: check-go
	@command -v "$(LINUX_CC)" >/dev/null 2>&1 || { printf 'WARNING: Linux amd64 C compiler not found: %s\n' '$(LINUX_CC)' >&2; exit 1; }
	@case "$$($(LINUX_CC) -dumpmachine 2>/dev/null)" in x86_64*linux*) ;; *) printf 'WARNING: %s is not a Linux amd64 compiler. Set LINUX_CC appropriately.\n' '$(LINUX_CC)' >&2; exit 1 ;; esac
	@mkdir -p $(DIST_DIR)/linux_amd64
	@printf 'int main(void) { return 0; }\n' | "$(LINUX_CC)" -x c - -l:libOpenCL.so.1 -o $(DIST_DIR)/linux_amd64/.opencl-link-check >/dev/null 2>&1 || { printf '%s\n' 'WARNING: Linux OpenCL loader libOpenCL.so.1 is not linkable with LINUX_CC.' >&2; exit 1; }
	@rm -f $(DIST_DIR)/linux_amd64/.opencl-link-check

check-windows: check-go
	@command -v sed >/dev/null 2>&1 && command -v grep >/dev/null 2>&1 || { printf '%s\n' 'WARNING: sed and grep are required to generate the Windows OpenCL import library.' >&2; exit 1; }
	@command -v "$(WINDOWS_CC)" >/dev/null 2>&1 || { printf 'WARNING: Windows amd64 C compiler not found: %s\n' '$(WINDOWS_CC)' >&2; exit 1; }
	@command -v "$(WINDOWS_DLLTOOL)" >/dev/null 2>&1 || { printf 'WARNING: Windows import-library tool not found: %s\n' '$(WINDOWS_DLLTOOL)' >&2; exit 1; }
	@case "$$($(WINDOWS_CC) -dumpmachine 2>/dev/null)" in x86_64*mingw*) ;; *) printf 'WARNING: %s is not a MinGW-w64 amd64 compiler. Set WINDOWS_CC appropriately.\n' '$(WINDOWS_CC)' >&2; exit 1 ;; esac
	@test -n "$(WINDOWS_LIB_DIR)" || { printf '%s\n' 'WARNING: cygpath is required in the Windows MSYS2 shell.' >&2; exit 1; }

linux: check-linux
	@mkdir -p $(DIST_DIR)/linux_amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) -C trustwallet_extractor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/linux_amd64/trustwallet_extractor.bin .
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC="$(LINUX_CC)" $(GO) -C trustwallet_decryptor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/linux_amd64/trustwallet_decryptor.bin .

windows: check-windows
	@mkdir -p $(WIN_BUILD_DIR) $(DIST_DIR)/windows_amd64
	@{ printf 'LIBRARY OpenCL.dll\nEXPORTS\n'; sed -n 's/^extern .* \(cl[A-Za-z0-9_]*\)(.*/  \1/p' trustwallet_decryptor/bridge.c; } > $(WIN_BUILD_DIR)/OpenCL.def
	@grep -q '^  cl' $(WIN_BUILD_DIR)/OpenCL.def || { printf '%s\n' 'WARNING: Cannot extract OpenCL API exports from bridge.c.' >&2; exit 1; }
	"$(WINDOWS_DLLTOOL)" -m i386:x86-64 -d $(WIN_BUILD_DIR)/OpenCL.def -D OpenCL.dll -l $(WIN_BUILD_DIR)/libOpenCL.a
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) -C trustwallet_extractor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/windows_amd64/trustwallet_extractor.exe .
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC="$(WINDOWS_CC)" CGO_LDFLAGS="-L$(WINDOWS_LIB_DIR) $${CGO_LDFLAGS:-}" $(GO) -C trustwallet_decryptor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/windows_amd64/trustwallet_decryptor.exe .

linux-cpu: check-go
	@mkdir -p $(DIST_DIR)/linux_amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) -C trustwallet_extractor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/linux_amd64/trustwallet_extractor.bin .
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) -C trustwallet_decryptor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/linux_amd64/trustwallet_decryptor.bin .

windows-cpu: check-go
	@mkdir -p $(DIST_DIR)/windows_amd64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) -C trustwallet_extractor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/windows_amd64/trustwallet_extractor.exe .
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) -C trustwallet_decryptor build $(GO_BUILD_FLAGS) -o ../$(DIST_DIR)/windows_amd64/trustwallet_decryptor.exe .

UNICORN_PREFIX ?= $(shell brew --prefix unicorn 2>/dev/null)
export CGO_CFLAGS  += -I$(UNICORN_PREFIX)/include
export CGO_LDFLAGS += -L$(UNICORN_PREFIX)/lib

GUEST := guest.dylib

.PHONY: all run clean

all: $(GUEST)

$(GUEST): guest/guest.c
	clang -arch arm64 -shared -fPIC -O0 \
		-fno-stack-protector -fno-asynchronous-unwind-tables \
		-o $@ $<
	file $@
	nm -gU $@
	nm -u $@

run: $(GUEST)
	go run .

clean:
	rm -f $(GUEST) uc-macho

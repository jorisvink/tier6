# tier6 Makefile

CC?=cc
OBJDIR?=obj
VERSION=$(OBJDIR)/version

BIN=tier6
DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin

CFLAGS+=-std=c99 -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2 -fPIC
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -g
CFLAGS+=-Iinclude

CFLAGS+=$(shell pkg-config --cflags libkyrka)
LDFLAGS+=$(shell pkg-config --libs libkyrka)

SRC=	src/tier6.c \
	src/config.c \
	src/discovery.c \
	src/peer.c \
	src/tap.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
endif

ifeq ("$(COVERAGE)", "1")
	CFLAGS+=-fprofile-arcs -ftest-coverage
endif

ifeq ("$(OSNAME)", "")
OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
endif

ifeq ("$(OSNAME)", "linux")
	SRC+=src/platform_linux.c
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "openbsd")
	SRC+=src/platform_openbsd.c
	CFLAGS+=-DPLATFORM_OPENBSD
endif

all: $(BIN)

OBJS=	$(SRC:%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

all:
	$(MAKE) $(OBJDIR)
	$(MAKE) $(BIN)

$(BIN): $(OBJS) $(VERSION).c
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c $< -o $@

src/tier6.c: $(VERSION).c

$(VERSION).c: $(OBJDIR) force
	@if [ -f RELEASE ]; then \
		printf "const char *tier6_build_rev = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION)_gen; \
	elif [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION)_gen; \
		printf "const char *tier6_build_rev = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION)_gen; \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *tier6_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION)_gen;
	@if [ -f $(VERSION).c ]; then \
		cmp -s $(VERSION)_gen $(VERSION).c; \
		if [ $$? -ne 0 ]; then \
			cp $(VERSION)_gen $(VERSION).c; \
		fi \
	else \
		cp $(VERSION)_gen $(VERSION).c; \
	fi

install: $(BIN)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)

clean:
	rm -f $(VERSION)
	rm -rf $(OBJDIR) $(BIN)

.PHONY: all clean force

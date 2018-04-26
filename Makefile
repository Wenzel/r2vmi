include vmi.mk
include r2.mk

CFLAGS = -Wall -fPIC
LDFLAGS = -shared
CFLAGS += $(R2_CFLAGS) $(VMI_CFLAGS)
LDFLAGS += $(R2_LDFLAGS) $(VMI_LDFLAGS)


all: $(TARGETS)

%.$(SO_EXT): %.c profile.c utils.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

install: all
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(TARGETS) $(R2_USER_PLUGINS)

clean:
	rm -f $(TARGETS)

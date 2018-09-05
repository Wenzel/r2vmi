SO_EXT=so
R2_CFLAGS+=$(shell pkg-config --cflags r_bin r_util)
R2_LDFLAGS+=$(shell pkg-config --libs r_util r_bin)
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

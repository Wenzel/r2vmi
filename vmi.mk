TARGETS = io_vmi.so debug_vmi.so
VMI_CFLAGS = $(shell pkg-config --cflags libvmi glib-2.0 json-c)
VMI_LDFLAGS = $(shell pkg-config --libs libvmi glib-2.0 json-c)

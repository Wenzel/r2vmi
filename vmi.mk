TARGETS = io_vmi.so debug_vmi.so
VMI_CFLAGS = $(shell pkg-config --cflags libvmi) $(shell pkg-config --cflags glib-2.0)
VMI_LDFLAGS = $(shell pkg-config --libs libvmi) $(shell pkg-config --libs glib-2.0)

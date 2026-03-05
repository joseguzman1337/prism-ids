MIN_CPU ?= native
TARGET_CPU ?= native

ARCH_CFLAGS := \
	-march=$(MIN_CPU) \
	-mtune=$(TARGET_CPU) \

TARGET_CFLAGS := \
	$(ARCH_CFLAGS) \
	-static-libgcc

# DEBUG_CFLAGS := -Og -fno-inline-functions

TARGET_DEFS := -D_GNU_SOURCE

OPT_CFLAGS := \
	-O2 \
	-ggdb \
	-flto -fwhole-program -fno-fat-lto-objects \
	-finline-functions \
	-ftree-partial-pre \
	-fgcse-after-reload \
	-fipa-cp-clone \
	-fipa-pta

WARN_CFLAGS := \
	-Wall \
	-Wsign-compare \
	-Wcast-align \
	-Wmissing-declarations \
	-Wmissing-noreturn \
	-Wmissing-format-attribute \
	-Wmaybe-uninitialized \
	-Wlogical-op \
	-Wduplicated-cond \
	-Wduplicated-branches \
	-Wlogical-op \
	-Wrestrict \
	-Wnull-dereference \
	-Wimplicit-fallthrough \
	-Wswitch-enum

# INCLUDES := -Iinclude

CC := $(CROSS_COMPILE)gcc
HOSTCC := gcc
CFLAGS := \
	$(TARGET_CFLAGS) \
	$(OPT_CFLAGS) \
	$(DEBUG_CFLAGS) \
	$(WARN_CFLAGS) \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Wjump-misses-init \
	$(INCLUDES) \
	$(TARGET_DEFS)

CPP := g++
CPPFLAGS := \
	$(TARGET_CFLAGS) \
	$(OPT_CFLAGS) \
	-fno-exceptions \
	-fno-rtti \
	-Wno-deprecated-declarations \
	-DGOOGLE_PROTOBUF_NO_RTTI=1 \
	$(DEBUG_CFLAGS) \
	$(WARN_CFLAGS) \
	$(INCLUDES) \
	$(TARGET_DEFS)

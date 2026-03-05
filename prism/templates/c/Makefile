include mk/header.mk
include mk/compiler.mk

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

include mk/rules.mk

include mk/hyperscan.mk
include mk/prism.rules.mk

# This make fragment lists out all of the generated source files for hooks.
-include $(SRC_DIR)/hook.list.mk

# This make fragment lists out all of the hyperscan databases that we want to
# include in to the program. A pattern rule in mk/prism.rules.mk performs the
# actual compilation of the hyperscan databases from their source files
-include $(SRC_DIR)/hsdb.list.mk

# This object file collects up all the compiled hyperscan databases in to the
# .rodata section, using the incbin assembler directive, and it emits symbols
# of the form {name}_buf and {name}_size so we can locate them at runtime for
# deserialization
$(SRC_DIR)/hsdb.S: $(PRISM_HSDB_OBJ)

PRISM_SRC := \
	hsdb.S \
	prism_rules.c \
	$(PRISM_HOOK_SRC) \
	test_args.c \
	main.c

PRISM_LIB := $(HS_RT_LDFLAGS) -lzstd -lz

$(eval $(call make_bin,prism,$(PRISM_SRC),$(PRISM_LIB)))
$(eval $(call add_cflags,$(PRISM_SRC),$(HS_CFLAGS)))

include mk/targets.mk
include mk/deps.mk

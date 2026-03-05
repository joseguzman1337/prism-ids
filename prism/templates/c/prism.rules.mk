# TODO: we will wanto tune these for the specific EC2 instance-type that we're
# going to be running on
HSC_FLAGS := --native --block

$(OBJ_DIR)/%.hsdb: $(SRC_DIR)/%.hsdef $(BIN_DIR)/hyperc $(MAKEFILE_LIST) | $(call dstamp,$$(@D))
	$(info hyperc: $(patsubst $(OBJ_DIR)/%,%,$@))
	$(BIN_DIR)/hyperc $(HSC_FLAGS) $< $@

HSC_SRC := $(SRC_DIR)/hyperc.c

# There are no intermediate object files here because we want to compile with
# the host compiler, not the target compiler. If we had multiple host programs
# which share objects then we may want separate host and target obj dirs and
# separate rules, but this project is too small to require that machinery
$(BIN_DIR)/hyperc: $(HSC_SRC) $(MAKEFILE_LIST) | $(call dstamp,$$(@D))
	$(info host-compile: $(patsubst $(OBJ_DIR)/%,%,$@))
	$(HOSTCC) $(CFLAGS) $(HS_CFLAGS) -o $@ $(HSC_SRC) $(HS_LDFLAGS)

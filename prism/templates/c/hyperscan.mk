HS_LIBS := -lhs
HS_RT_LIBS := -lhs_runtime
HS__LDFLAGS := $(shell pkg-config --libs-only-L libhs)

HS_CFLAGS := $(shell pkg-config --cflags libhs)
HS_LDFLAGS := $(HS__LDFLAGS) $(HS_LIBS)
HS_RT_LDFLAGS := $(HS__LDFLAGS) $(HS_RT_LIBS)

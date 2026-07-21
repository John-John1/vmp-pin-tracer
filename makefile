PIN_ROOT = pin
TOOL_ROOTS := vmp_tracer

include $(PIN_ROOT)/source/tools/Config/makefile.config
include makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules

# 

PROJECT_ROOT = ..
include $(PROJECT_ROOT)/Makefile.rules

OUT_DIR = $(PROJECT_ROOT)/build$(TARGET_ARCH)
BUILD_DIR = build$(TARGET_ARCH)
TARGET = $(OUT_DIR)/libapverify.a

.PHONY: all init clean distclean

C_FLAGS += -I. -I$(PROJECT_ROOT)/common -static-libgcc -Wall -O2
CPP_FLAGS += -I. -I$(PROJECT_ROOT)/common -Wall -O2

SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

all: $(TARGET)

init:
	@[ -d $(OUT_DIR) ] || mkdir $(OUT_DIR)
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.cpp
	$(GPP) -o $@ -c $(CPP_FLAGS) $<

$(TARGET): init $(OBJS)
	$(MAKE_STATIC_LIB) $(TARGET) $(OBJS) $(LDFLAGS)

clean: 
	@rm -rf $(BUILD_DIR)/* $(TARGET)

distclean: clean
	@rm -rf build32/ build64/

# 

PROJECT_ROOT = ..
include $(PROJECT_ROOT)/Makefile.rules

.PHONY: all init clean distclean demo

CPP_FLAGS += -I. -I$(PROJECT_ROOT)/common -Wall

OUT_DIR = $(PROJECT_ROOT)/build$(TARGET_ARCH)
BUILD_DIR = build$(TARGET_ARCH)
TARGET = $(OUT_DIR)/demo

LIBS = $(OUT_DIR)/libapclient.a $(OUT_DIR)/libapverify.a $(OUT_DIR)/libapcommon.a

SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

all: $(TARGET) 

init:
	@[ -d $(OUT_DIR) ] || mkdir $(OUT_DIR); true
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR); true

$(BUILD_DIR)/%.o: %.cpp
	$(GPP) -o $@ -c $(CPP_FLAGS) $<

$(TARGET): init $(OBJS)
	$(MAKE_STATIC_COMMAND) $@ $(OBJS) $(LIBS) $(LDFLAGS)

demo: $(TARGET)
	./$(TARGET) || exit 1

clean: 
	@rm -rf $(BUILD_DIR)/* $(TARGET)

distclean: clean
	@rm -rf msvc/Output/ msvc/ipch/ msvc/*.sdf msvc/*.suo build32/ build64/

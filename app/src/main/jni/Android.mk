LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := idacore
LOCAL_SRC_FILES := a64.cpp database.cpp pseudo.cpp jni_bridge.cpp
LOCAL_CPPFLAGS  := -std=c++17 -O2 -fexceptions
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)

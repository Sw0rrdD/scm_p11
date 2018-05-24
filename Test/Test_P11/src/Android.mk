

LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)

SRC=$(wildcard ./src/*.c)
SRC_LIST=$(notdir $(SRC))

LOCAL_SRC_FILES := $(SRC_LIST) 


LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../android_CMS/include \
	$(LOCAL_PATH)/


LOCAL_CFLAGS := -DSM2_WSM
LOCAL_LDLIBS := -llog -lstdc++ -lc -DSM2_WSM
LOCAL_LDLIBS += $(LOCAL_PATH)/../android_CMS/lib/$(BUILD_BIT)/libCMApi.so

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := test_CMApi
LOCAL_MODULE_CLASS := EXECUTABLES
include $(BUILD_EXECUTABLE)





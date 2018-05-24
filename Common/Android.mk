LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE 		:= Common
LOCAL_PRELINK_MODULE 	:= false
LOCAL_SRC_FILES 	:= $(LOCAL_PATH)/src/LogMsg.c \
			$(LOCAL_PATH)/src/WaOsPal.c

LOCAL_C_INCLUDES 	+= $(LOCAL_PATH)/include
LOCAL_LDLIBS 		+= -lm -llog 
include $(BUILD_SHARED_LIBRARY)

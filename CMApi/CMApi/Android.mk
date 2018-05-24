# CMAPI Makefile

#编译中间件so库
LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)



LOCAL_SRC_FILES:= \
	$(LOCAL_PATH)/pkcs15/ssp/ssp.c \
	$(LOCAL_PATH)/pkcs15/ssp/ssp_file.c \
	$(LOCAL_PATH)/pkcs15/ssp/ssp_obj.c \
	$(LOCAL_PATH)/pkcs15/ssp/ssp_sm.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-data.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-df.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-pubkey.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-skey.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-prkey.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15_tool.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-framework.c \
	$(LOCAL_PATH)/pkcs15/p15/init_card.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-pin.c \
	$(LOCAL_PATH)/pkcs15/p15/pkcs15-cert.c \
	$(LOCAL_PATH)/p11/src/sm4_process.c \
	$(LOCAL_PATH)/p11/src/p11_parallel.c \
	$(LOCAL_PATH)/p11/src/smvc.c \
	$(LOCAL_PATH)/p11/src/bn.c \
	$(LOCAL_PATH)/p11/src/p11_random.c \
	$(LOCAL_PATH)/p11/src/p11x_util.c \
	$(LOCAL_PATH)/p11/src/p11_dual.c \
	$(LOCAL_PATH)/p11/src/self_test.c \
	$(LOCAL_PATH)/p11/src/p11_thread.c \
	$(LOCAL_PATH)/p11/src/p11x_state.c \
	$(LOCAL_PATH)/p11/src/sm3_hmac.c \
	$(LOCAL_PATH)/p11/src/p11x_session.c \
	$(LOCAL_PATH)/p11/src/p11_sign.c \
	$(LOCAL_PATH)/p11/src/p11_verify.c \
	$(LOCAL_PATH)/p11/src/sm3_process.c \
	$(LOCAL_PATH)/p11/src/reader-pcsc.c \
	$(LOCAL_PATH)/p11/src/cetcsc.c \
	$(LOCAL_PATH)/p11/src/p11x_object.c \
	$(LOCAL_PATH)/p11/src/ecp.c \
	$(LOCAL_PATH)/p11/src/p11_crypt.c \
	$(LOCAL_PATH)/p11/src/p11_extend.c \
	$(LOCAL_PATH)/p11/src/libscdl.c \
	$(LOCAL_PATH)/p11/src/p11_key.c \
	$(LOCAL_PATH)/p11/src/p11_general.c \
	$(LOCAL_PATH)/p11/src/p11x_log.c \
	$(LOCAL_PATH)/p11/src/sm2_process.c \
	$(LOCAL_PATH)/p11/src/p11x_error.c \
	$(LOCAL_PATH)/p11/src/zuc_process.c \
	$(LOCAL_PATH)/p11/src/p11_digest.c \
	$(LOCAL_PATH)/p11/src/p11_token.c \
	$(LOCAL_PATH)/p11/src/unit.c \
	$(LOCAL_PATH)/p11/src/p11_session.c \
	$(LOCAL_PATH)/p11/src/apdu.c \
	$(LOCAL_PATH)/p11/src/p11x_slot.c \
	$(LOCAL_PATH)/p11/src/p11_object.c \
	$(LOCAL_PATH)/scp02/card.c \
	$(LOCAL_PATH)/scp02/crypt.c \
	$(LOCAL_PATH)/sm/rand/src/drnginterface/bcc.c \
	$(LOCAL_PATH)/sm/rand/src/drnginterface/drbg.c \
	$(LOCAL_PATH)/sm/rand/src/drnginterface/dnrg_test.c \
	$(LOCAL_PATH)/sm/rand/src/drnginterface/drbg_ctr.c \
	$(LOCAL_PATH)/sm/rand/src/approximate_entropy.c \
	$(LOCAL_PATH)/sm/rand/src/auto_relation.c \
	$(LOCAL_PATH)/sm/rand/src/bia_test.c \
	$(LOCAL_PATH)/sm/rand/src/block_frequent.c \
	$(LOCAL_PATH)/sm/rand/src/cumulative_sums.c \
	$(LOCAL_PATH)/sm/rand/src/dfft.c \
	$(LOCAL_PATH)/sm/rand/src/discrete_fouriter.c \
	$(LOCAL_PATH)/sm/rand/src/function.c \
	$(LOCAL_PATH)/sm/rand/src/rbg.c \
	$(LOCAL_PATH)/sm/rand/src/linear_complexity.c \
	$(LOCAL_PATH)/sm/rand/src/longest_run.c \
	$(LOCAL_PATH)/sm/rand/src/matrix.c \
	$(LOCAL_PATH)/sm/rand/src/mm_debug.c \
	$(LOCAL_PATH)/sm/rand/src/monobit_test.c \
	$(LOCAL_PATH)/sm/rand/src/poker.c \
	$(LOCAL_PATH)/sm/rand/src/rank.c \
	$(LOCAL_PATH)/sm/rand/src/run_distrubution.c \
	$(LOCAL_PATH)/sm/rand/src/runs.c \
	$(LOCAL_PATH)/sm/rand/src/serial.c \
	$(LOCAL_PATH)/sm/rand/src/universal.c \
	$(LOCAL_PATH)/sm/rand/src/estimating_mini_entropy.c \
	$(LOCAL_PATH)/sm/rand/RandChk/rand_chk.c \
	$(LOCAL_PATH)/sm/rand/RandChk/wst_rand_checker.c \
	$(LOCAL_PATH)/sm/zuc/zucinterface/zuc_core.c \
	$(LOCAL_PATH)/sm/zuc/zucinterface/eea3.c \
	$(LOCAL_PATH)/sm/zuc/zucinterface/eia3.c \
	$(LOCAL_PATH)/sm/zuc/zucinterface/zuc.c \
	$(LOCAL_PATH)/sm/sm3/sm3interface/sm3.c \
	$(LOCAL_PATH)/sm/sm3/sm3interface/sm3_core.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/ecdsa.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/ec_general.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_lib.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_asm.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/mm_basic_fun.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/key_ex.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_div.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/ecp_smpl.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_mont.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_mod.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_mul.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_shift.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_gcd.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/sm2_bn_add.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/rc4.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/eces.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/ec_lib.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/ec_mult.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/eccsm2_p256.c \
	$(LOCAL_PATH)/sm/sm2/sm2interface/kdf.c \
	$(LOCAL_PATH)/sm/sm4/sm4interface/sm4.c \
	$(LOCAL_PATH)/sm/sm4/sm4interface/sm4_core.c \
	$(LOCAL_PATH)/wsm_pcs/wsm_local_data_access/wsm_local_data_access.c \
	$(LOCAL_PATH)/wsm_pcs/wsm/wsm.c \
	$(LOCAL_PATH)/wsm_pcs/wsm/prf.c \
	$(LOCAL_PATH)/wsm_pcs/cmnc_pkg_msg/cmnc_pkg_msg.cc \
	$(LOCAL_PATH)/wsm_pcs/coop_cmd_msg/coop_content_msg.cc \
	$(LOCAL_PATH)/wsm_pcs/prod_cmd_msg/prod_content_msg.cc \
	$(LOCAL_PATH)/wsm_pcs/protocol/PublicDefine.pb.cc \
	$(LOCAL_PATH)/wsm_pcs/protocol/BusinessType.pb.cc \
	$(LOCAL_PATH)/wsm_pcs/protocol/CommunicatePackage.pb.cc \
	$(LOCAL_PATH)/wsm_pcs/protocol/CooperationCommandPackage.pb.cc \
	$(LOCAL_PATH)/wsm_pcs/protocol/ProductionCommandPackage.pb.cc


LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../../Common/include \
	$(LOCAL_PATH)/../../Communication/channel/include/ \
	$(LOCAL_PATH)/pkcs15/include \
	$(LOCAL_PATH)/p11/include \
	$(LOCAL_PATH)/p11/src \
	$(LOCAL_PATH)/sm/rand/include \
	$(LOCAL_PATH)/sm/rand/RandChk \
	$(LOCAL_PATH)/sm/zuc/include \
	$(LOCAL_PATH)/sm/sm2/include \
	$(LOCAL_PATH)/sm/sm3/include \
	$(LOCAL_PATH)/sm/sm4/include \
	$(LOCAL_PATH)/wsm_pcs/include \
	$(LOCAL_PATH)/wsm_pcs/wsm/ \
	$(LOCAL_PATH)/wsm_pcs/wsm_local_data_access/ \
	$(LOCAL_PATH)/wsm_pcs/protocol/ \
	$(LOCAL_PATH)/wsm_pcs/cmnc_pkg_msg/ \
	$(LOCAL_PATH)/wsm_pcs/coop_cmd_msg/ \
	$(LOCAL_PATH)/wsm_pcs/prod_cmd_msg/ \
	$(LOCAL_PATH)/wsm_pcs/protobuf/include/ \
	$(LOCAL_PATH)/wsm_pcs/wbcrypto/include/ \
	$(LOCAL_PATH)/../../Tools/soProtect/include/ \
	$(LOCAL_PATH)/../../Tools/IntegrityCheck/include/ \
	$(LOCAL_PATH)/scp02/ 

	
#LOCAL_CFLAGS := -fPIE -DSM2_WSM -D$(CMAPI_VERSION_INFO) -fPIC
#LOCAL_CPPFLAGS += -frtti -DSM2_WSM -D$(CMAPI_VERSION_INFO) -fPIC

LOCAL_CFLAGS := -fPIE -D$(CMAPI_VERSION_INFO) -DSM2_WSM -fPIC
LOCAL_CPPFLAGS += -frtti -D$(CMAPI_VERSION_INFO) -DSM2_WSM -fPIC

LOCAL_LDLIBS := -llog -lstdc++ -ldl -lc -lm -fPIE 

ifeq ($(IS_BUILD_FOR_SO_PROTECT), 1)

#需要安全防护
#包含gnustl_static库所在路径
ifeq ($(APP_ABI), arm64-v8a)
#SOPROTECT_PATH=$(LOCAL_PATH)/../../Tools/soProtect/lib/64/arm64-v8a
else ifeq ($(APP_ABI), armeabi-v7a)
SOPROTECT_PATH=$(LOCAL_PATH)/../../Tools/soProtect/lib/32/armeabi-v7a
else ifeq ($(APP_ABI), armeabi)
SOPROTECT_PATH=$(LOCAL_PATH)/../../Tools/soProtect/lib/32/armeabi
endif

LOCAL_LDLIBS += $(SOPROTECT_PATH)/libsoProtect.a 

LOCAL_CFLAGS += -DSO_PROTECT 
LOCAL_CPPFLAGS += -DSO_PROTECT 

#for IntegrityCheck
LOCAL_LDLIBS +=$(LOCAL_PATH)/../../Tools/IntegrityCheck/lib/libIntegrityCheck.a
LOCAL_LDLIBS +=$(LOCAL_PATH)/../../Tools/IntegrityCheck/lib/libz.a
endif


ifeq ($(APP_ABI), arm64-v8a)
STL_PATH=$(NDK_BUILD_PATH)/sources/cxx-stl/gnu-libstdc++/4.9/libs/arm64-v8a
else ifeq ($(APP_ABI), armeabi-v7a)
STL_PATH=$(NDK_BUILD_PATH)/sources/cxx-stl/gnu-libstdc++/4.9/libs/armeabi-v7a
else ifeq ($(APP_ABI), armeabi)
STL_PATH=$(NDK_BUILD_PATH)/sources/cxx-stl/gnu-libstdc++/4.9/libs/armeabi
endif

LOCAL_LDLIBS += $(LOCAL_PATH)/../../build/android_CMS/lib/$(BUILD_BIT)/libwbcrypto.so
LOCAL_LDLIBS += $(LOCAL_PATH)/../../build/android_CMS/lib/$(BUILD_BIT)/libchannel.so
LOCAL_LDLIBS += $(LOCAL_PATH)/../../build/android_CMS/lib/$(BUILD_BIT)/libCommon.so



LOCAL_LDLIBS += $(LOCAL_PATH)/../../build/android_CMS/lib/$(BUILD_BIT)/libprotobuf.a
LOCAL_LDLIBS += -L$(STL_PATH) -lgnustl_static




ifeq ($(IS_BUILD_FOR_APK), 1)
LOCAL_CFLAGS += -DBUILD_FOR_APK
LOCAL_CPPFLAGS += -DBUILD_FOR_APK
endif


LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libCMApi
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
include $(BUILD_SHARED_LIBRARY)







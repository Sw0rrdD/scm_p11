adb shell mount -o rw,remount,barrier=1 /system 


cd android_bin/32

adb push ca.cer /system/bin/test_CMApi/
adb push demo_CMApi /system/bin/test_CMApi/
adb push test_CMApi /system/bin/test_CMApi/
adb push libchannel.so /system/bin/test_CMApi/
adb push libCMApi.so /system/bin/test_CMApi/
adb push libCommon.so /system/bin/test_CMApi/
adb push libCryptoLib.so /system/bin/test_CMApi/
adb push libprotobuf.so /system/bin/test_CMApi/
adb push libsm13algrithm.so /system/bin/test_CMApi/
adb push libTcUtility.so /system/bin/test_CMApi/
adb push libwbcrypto.so /system/bin/test_CMApi/
adb push libwsteay10.so /system/bin/test_CMApi/
adb push libWSTSM234SoftEngine.so /system/bin/test_CMApi/
adb push libwstssl10.so /system/bin/test_CMApi/
adb push libiconv.so /system/bin/test_CMApi/

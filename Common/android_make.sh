#保存当前路径
CURRENT_PATH=$(pwd)
#ndk-build路径
NDK_BUILD=$1

#生成输出目录

rm -rf android_lib

mkdir android_lib
mkdir android_lib/32
mkdir android_lib/64


#编译32位
#清理工程
echo "**************************ndk-build clean all tmp files*************************"
$NDK_BUILD clean APP_ABI=armeabi-v7a APP_PLATFORM=android-21 NDK_DEBUG=0 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

#编译工程
echo "*************************ndk-build for android*************************"
$NDK_BUILD  APP_ABI=armeabi-v7a APP_PLATFORM=android-21 NDK_DEBUG=0 APP_STL=gnustl_static BUILD_BIT=32 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

mv libs/armeabi-v7a/libCommon.so android_lib/32/libCommon.so


#编译64位  

#清理工程
echo "**************************ndk-build clean all tmp files*************************"
$NDK_BUILD clean APP_ABI=arm64-v8a APP_PLATFORM=android-21 NDK_DEBUG=0 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

#编译工程
echo "*************************ndk-build for android*************************"
$NDK_BUILD  APP_ABI=arm64-v8a APP_PLATFORM=android-21 NDK_DEBUG=0 APP_STL=gnustl_static BUILD_BIT=64 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

mv libs/arm64-v8a/libCommon.so android_lib/64/libCommon.so

#删除编译产生的临时目录
cd $CURRENT_PATH
rm -rf libs
rm -rf obj

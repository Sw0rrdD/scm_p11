
#保存当前路径
CURRENT_PATH=$(pwd)

NDK_BUILD=ndk-build

#生成输出目录

rm -rf android_bin

mkdir android_bin
mkdir android_bin/32
mkdir android_bin/64


#编译32位
#清理工程
echo "**************************ndk-build clean all tmp files*************************"
$NDK_BUILD clean APP_ABI=armeabi-v7a APP_PLATFORM=android-21 NDK_DEBUG=0 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./src/Android.mk

#编译工程
echo "*************************ndk-build for android*************************"
$NDK_BUILD  APP_ABI=armeabi-v7a APP_PLATFORM=android-21 NDK_DEBUG=0 APP_STL=gnustl_static BUILD_BIT=32 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./src/Android.mk

mv libs/armeabi-v7a/test_CMApi android_bin/32/test_CMApi

cd $CURRENT_PATH
cp android_CMS/lib/32/* android_bin/32



#编译64位  #FIXME 部分64位的依赖库暂时没有

#清理工程
#echo "**************************ndk-build clean all tmp files*************************"
#$NDK_BUILD clean APP_ABI=arm64-v8a APP_PLATFORM=android-21 NDK_DEBUG=0 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./src/Android.mk

#编译工程
#echo "*************************ndk-build for android*************************"
#$NDK_BUILD  APP_ABI=arm64-v8a APP_PLATFORM=android-21 NDK_DEBUG=0 APP_STL=gnustl_static BUILD_BIT=64 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./src/Android.mk

#mv libs/arm64-v8a/test_CMApi android_bin/64/test_CMApi

#cd $CURRENT_PATH
#cp android_CMS/lib/64/* android_bin/64


#删除编译产生的临时目录
cd $CURRENT_PATH
rm -rf libs
rm -rf obj


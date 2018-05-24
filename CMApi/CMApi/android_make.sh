#保存当前路径
CURRENT_PATH=$(pwd)

#设置NDK
NDK_BUILD_PATH=$1
NDK_BUILD=$NDK_BUILD_PATH/ndk-build

#是否编译为APK运行版本
BUILD_FOR_APK=$2

#是否需要安全加固
BUILD_FOR_SO_PROTECT=$3


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
#FIXME  CMAPI_VERSION_INFO指定当前CMApi的版本信息
$NDK_BUILD  APP_ABI=armeabi-v7a APP_PLATFORM=android-21 NDK_DEBUG=0 APP_STL=gnustl_static   \
	BUILD_BIT=32 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk CMAPI_VERSION_INFO="CMAPI_VERSION_INFO=\\\"CMApi\ version\ is:\ V1.1.3\ 2017-10-28\\\"" \
	NDK_BUILD_PATH=$NDK_BUILD_PATH IS_BUILD_FOR_SO_PROTECT=$BUILD_FOR_SO_PROTECT IS_BUILD_FOR_APK=$BUILD_FOR_APK

mv libs/armeabi-v7a/libCMApi.so android_lib/32/libCMApi.so


#编译64位  #FIXME 64位有的依赖库暂时还没有

#清理工程
#echo "**************************ndk-build clean all tmp files*************************"
#$NDK_BUILD clean APP_ABI=arm64-v8a APP_PLATFORM=android-21 NDK_DEBUG=0 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

#编译工程
#echo "*************************ndk-build for android*************************"
#FIXME  CMAPI_VERSION_INFO指定当前CMApi的版本信息
#$NDK_BUILD  APP_ABI=arm64-v8a APP_PLATFORM=android-21 NDK_DEBUG=0 APP_STL=gnustl_static   \
#	BUILD_BIT=64 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk CMAPI_VERSION_INFO="CMAPI_VERSION_INFO=\\\"CMApi\ version\ is:\ V1.1.3\ 2017-10-28\\\"" \
#	NDK_BUILD_PATH=$NDK_BUILD_PATH IS_BUILF_FOR_PROTECT=$BUILF_FOR_PROTECT IS_BUILD_FOR_APK=$BUILD_FOR_APK

#mv libs/arm64-v8a/libCMApi.so android_lib/64/libCMApi.so

#删除编译产生的临时目录
cd $CURRENT_PATH
rm -rf libs
rm -rf obj

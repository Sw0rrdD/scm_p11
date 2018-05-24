#保存当前路径
CURRENT_PATH=$(pwd)

#生成输出目录

rm -rf ubuntu_lib

mkdir ubuntu_lib
mkdir ubuntu_lib/32
mkdir ubuntu_lib/64

cd src 

#编译32位 #FIXME目前依赖库只有64位
make clean
make WST_BUILD_CFG="-m32 -O2 -g0 -fpermissive -DSM2_WSM" BUILD_BIT=32

mv libCommon.so ../ubuntu_lib/32

make clean

#编译64位 
make clean
make WST_BUILD_CFG="-m64 -O2 -g0 -fpermissive -DSM2_WSM" BUILD_BIT=64

mv libCommon.so ../ubuntu_lib/64
make clean








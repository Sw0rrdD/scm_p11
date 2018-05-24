#保存当前路径
CURRENT_PATH=$(pwd)

#生成输出目录

rm -rf ubuntu_lib

mkdir ubuntu_lib
mkdir ubuntu_lib/32
mkdir ubuntu_lib/64



#编译32位
make clean
make WST_BUILD_CFG="-m32 -O2 -g0 -fpermissive -fPIC -DSM2_WSM -DCMAPI_VERSION_INFO=\\\"CMApi\ version\ is:\ V1.1.3\ 2017-10-28\\\""

mv debug/libCMApi.so ubuntu_lib/32/
make clean

#编译64位
make clean
make WST_BUILD_CFG="-m64 -O2 -g0 -fpermissive -fPIC -DSM2_WSM -DCMAPI_VERSION_INFO=\\\"CMApi\ version\ is:\ V1.1.3\ 2017-10-28\\\""

mv debug/libCMApi.so ubuntu_lib/64/
make clean

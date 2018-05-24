#保存当前路径
CURRENT_PATH=$(pwd)

#生成输出目录

rm -rf ubuntu_bin

mkdir ubuntu_bin
mkdir ubuntu_bin/32
mkdir ubuntu_bin/64




cd src

#编译32位 #FIXME目前依赖库只有64位
#make clean
#make WST_BUILD_CFG="-m32 -O2 -g0 -fpermissive -DSM2_WSM" BUILD_BIT=32

#mv test_CMApi ../ubuntu_bin/32

#make clean

#cd $CURRENT_PATH
#cp ubuntu_CMS/lib/32/* ubuntu_bin/32
#cp ubuntu_CMS/lib/32/.e2.wst ubuntu_bin/32



make clean
make WST_BUILD_CFG="-m64 -O2 -g0 -fpermissive -DSM2_WSM" BUILD_BIT=64
mv test_p11 ../ubuntu_bin/64

make clean

cd $CURRENT_PATH
cp ../../build/ubuntu_CMS/lib/64/* ubuntu_bin/64 -rf


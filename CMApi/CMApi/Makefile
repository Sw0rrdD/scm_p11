#设置编译器
CC=g++
GPP=g++

#debug文件夹里的makefile文件需要最后执行，所以这里需要执行的子目录要排除debug文件夹，这里使用awk排除了debug文件夹，读取剩下的文件夹
#SUBDIRS=$(shell ls -l | grep ^d | awk '{if($$9 != "debug") print $$9}')
SUBDIRS=$(shell ls -l | grep -v -E "debug|wsm_pcs|android_lib|ubuntu_lib" | grep ^d | awk '{print $$9}')

#记住当前工程的根目录路径
ROOT_DIR=$(shell pwd)

#可执行程序
BIN=test_p11

#动态库程序
DYNAMIC=libCMApi.so

#目标文件所在的目录
OBJS_DIR=debug

#头文件路径
INCLUDE_DIR += -I$(ROOT_DIR)/p11/include
INCLUDE_DIR += -I$(ROOT_DIR)/pkcs15/include
INCLUDE_DIR += -I$(ROOT_DIR)/p11/src
INCLUDE_DIR += -I$(ROOT_DIR)/p11/test
INCLUDE_DIR += -I$(ROOT_DIR)/sm/sm2/include
INCLUDE_DIR += -I$(ROOT_DIR)/sm/sm3/include
INCLUDE_DIR += -I$(ROOT_DIR)/sm/sm4/include
INCLUDE_DIR += -I$(ROOT_DIR)/sm/zuc/include
INCLUDE_DIR += -I$(ROOT_DIR)/sm/rand/include
INCLUDE_DIR += -I$(ROOT_DIR)/sm/rand/RandChk 
INCLUDE_DIR += -I$(ROOT_DIR)/../../Common/include/
INCLUDE_DIR += -I$(ROOT_DIR)/wsm_pcs/include
INCLUDE_DIR += -I$(ROOT_DIR)/wsm_pcs/wsm
INCLUDE_DIR += -I$(ROOT_DIR)/scp02
INCLUDE_DIR += -I$(ROOT_DIR)/../../Tools/soProtect/include/

#获取当前目录下的c文件集，放在变量CUR_SOURCE中
CUR_SOURCE=${wildcard *.c}

#将对应的c文件名转为o文件后放在下面的CUR_OBJS变量中
CUR_OBJS=${patsubst %.c, %.o, $(CUR_SOURCE)}

#将以下变量导出到子shell中，本次相当于导出到子目录下的makefile中
export CC BIN OBJS_DIR BIN_DIR ROOT_DIR INCLUDE_DIR WST_BUILD_CFG

$(shell mkdir -p ${OBJS_DIR})

#注意这里的顺序，需要先执行SUBDIRS最后才能是DEBUG
all:$(SUBDIRS) $(CUR_OBJS) DEBUG

#递归执行子目录下的makefile文件，这是递归执行的关键
$(SUBDIRS):ECHO
	make -C $@
DEBUG:ECHO
	#$(GPP) $(WST_BUILD_CFG) -o $(ROOT_DIR)/$(OBJS_DIR)/$(BIN) $(ROOT_DIR)/$(OBJS_DIR)/*.o -L$(WSM_PCS_LIB_DIR) -lwsm_pcs -lchannel -lwbcrypto -lssl -lcrypto -lprotobuf -ldl -lpthread -lm -lrt
	#-fPIC　-shared -fpermissive -DSM2_WSM 
	$(GPP) -fPIC -shared -fpermissive $(WST_BUILD_CFG) -o $(ROOT_DIR)/$(OBJS_DIR)/$(DYNAMIC) $(ROOT_DIR)/$(OBJS_DIR)/*.o 
	@rm $(OBJS_DIR)/*.o
	#@cp -rf $(WSM_PCS_LIB_DIR)/*.* $(ROOT_DIR)/$(OBJS_DIR)/
	#@cp -rf $(WSM_PCS_LIB_DIR)/.e2.wst $(ROOT_DIR)/$(OBJS_DIR)/
ECHO:
	@echo $(SUBDIRS)

#将c文件编译为o文件，并放在指定放置目标文件的目录中即OBJS_DIR
$(CUR_OBJS):%.o:%.c
	$(CC) -c $^ -o $(ROOT_DIR)/$(OBJS_DIR)/$@
clean:
	@rm -rf $(ROOT_DIR)/$(OBJS_DIR)

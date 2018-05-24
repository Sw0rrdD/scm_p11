#添加源文件目录
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/p11/src
					SRCS_LIST_P11_SRC)
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/pkcs15/p15
					SRCS_LIST_PKCS15_P15)
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/pkcs15/ssp
					SRCS_LIST_PKCS15_SSP)
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/scp02
					SRCS_LIST_SCP02)
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/sm/rand/RandChk
					SRCS_LIST_SM_RAND_RANDCHK)
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/sm/rand/src
					SRCS_LIST_SM_RAND_SRC)
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/sm/rand/src/drnginterface
					SRCS_LIST_RAND_SRC_DRNGINTERFACE)
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/sm/sm2/sm2interface
					SRCS_LIST_SM2_SM2INTERFACE)					
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/sm/sm3/sm3interface
					SRCS_LIST_SM3_SM3INTERFACE)	
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/sm/sm4/sm4interface
					SRCS_LIST_SM4_SM4INTERFACE)	
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/sm/zuc/zucinterface
					SRCS_LIST_ZUC_ZUCINTERFACE)	
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/cmnc_pkg_msg
					SRCS_LIST_WSM_PCS_CMNC_PKG_MSG)	
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/coop_cmd_msg
					SRCS_LIST_WSM_PCS_COOP_CMD_MSG)	
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/prod_cmd_msg
					SRCS_LIST_WSM_PCS_PROD_CMD_MSG)	
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/protocol
					SRCS_LIST_WSM_PCS_PROTOCOL)	
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/wsm
					SRCS_LIST_WSM_PCS_WSM)						
AUX_SOURCE_DIRECTORY(
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/wsm_local_data_access
					SRCS_LIST_WSM_PCS_WSM_LOCAL_DATA_ACCESS)		
					
#工程名称
PROJECT(cmapi)

#头文件搜索路径
INCLUDE_DIRECTORIES(
					${CMAKE_SOURCE_DIR}/Common/include
					${CMAKE_SOURCE_DIR}/Tools/soProtect/include
					${CMAKE_SOURCE_DIR}/Communication/channel/include
					
					${CMAKE_CURRENT_SOURCE_DIR}/p11/include
					${CMAKE_CURRENT_SOURCE_DIR}/p11/src
					${CMAKE_CURRENT_SOURCE_DIR}/pkcs15/include
					${CMAKE_CURRENT_SOURCE_DIR}/scp02
					${CMAKE_CURRENT_SOURCE_DIR}/sm/rand/include
					${CMAKE_CURRENT_SOURCE_DIR}/sm/rand/RandChk
					${CMAKE_CURRENT_SOURCE_DIR}/sm/sm2/include
					${CMAKE_CURRENT_SOURCE_DIR}/sm/sm3/include
					${CMAKE_CURRENT_SOURCE_DIR}/sm/sm4/include
					${CMAKE_CURRENT_SOURCE_DIR}/sm/zuc/include
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/cmnc_pkg_msg
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/coop_cmd_msg
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/include
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/prod_cmd_msg
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/protocol
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/wbcrypto/include
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/wsm
					${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/wsm_local_data_access
					
					IF(<${PLATFORM_LABLE}|string> STREQUAL <${__APPLE__}|string>)
						${CMAKE_SOURCE_DIR}/extern_module/ios/protobuf/arm64/include
					ELSE()
						${CMAKE_CURRENT_SOURCE_DIR}/wsm_pcs/protobuf/include
					ENDIF()
										
					IF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_WINDOWS}|string>)
						${CMAKE_SOURCE_DIR}/extern_module/${PLATFORM_LABLE}/${ARCH_LABLE}/pthread/include
						${CMAKE_SOURCE_DIR}/extern_module/${PLATFORM_LABLE}/${ARCH_LABLE}/dirent						
					ENDIF()
					)

SET(SRCS_LIST

	${SRCS_LIST_P11_SRC}
	${SRCS_LIST_PKCS15_P15}
	${SRCS_LIST_PKCS15_SSP}
	${SRCS_LIST_SCP02}
	${SRCS_LIST_SM_RAND_RANDCHK}
	${SRCS_LIST_SM_RAND_SRC}
	${SRCS_LIST_RAND_SRC_DRNGINTERFACE}
	${SRCS_LIST_SM2_SM2INTERFACE}					
	${SRCS_LIST_SM3_SM3INTERFACE}	
	${SRCS_LIST_SM4_SM4INTERFACE}	
	${SRCS_LIST_ZUC_ZUCINTERFACE}	
	)

SET(SRCS_LIST_WSM_PCS

	${SRCS_LIST_WSM_PCS_CMNC_PKG_MSG}	
	${SRCS_LIST_WSM_PCS_COOP_CMD_MSG}	
	${SRCS_LIST_WSM_PCS_PROD_CMD_MSG}	
	${SRCS_LIST_WSM_PCS_PROTOCOL}	
	${SRCS_LIST_WSM_PCS_WSM}						
	${SRCS_LIST_WSM_PCS_WSM_LOCAL_DATA_ACCESS}
	)
	
IF(<${CMAKE_BUILD_TYPE}|string> STREQUAL <Debug|string>)
SET(PROBUFFER_LIB_windows ${CMAKE_SOURCE_DIR}/extern_module/windows/x86/Debug/libprotobufd.lib)
ELSEIF(<${CMAKE_BUILD_TYPE}|string> STREQUAL <Release|string>)
SET(PROBUFFER_LIB_windows ${CMAKE_SOURCE_DIR}/extern_module/windows/x86/Release/libprotobuf.lib)
ENDIF()

#针对平台配置
IF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_APPLE}|string>)

	ADD_DEFINITIONS(-DSM2_WSM)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti ")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
	
	ADD_LIBRARY ( 
			cmapi
			SHARED
			${SRCS_LIST}
			${SRCS_LIST_WSM_PCS}
			)

	target_link_libraries(		
			cmapi
		

			common
			channel
			${CMAKE_SOURCE_DIR}/extern_module/ios/protobuf/arm64/lib/libprotobuf.a
			${CMAKE_SOURCE_DIR}/extern_module/ios/wsm/libwhitecrypto.a
			) 
 set_target_properties(cmapi PROPERTIES BUILD_WITH_INSTALL_RPATH 1 INSTALL_NAME_DIR "@rpath")
	
ELSEIF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_UNIX}|string>)
	#设置编译器参数
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -fPIC")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fpermissive -fPIC") 

	#生成wsm_pcs库文件
	ADD_LIBRARY ( 
			wsm_pcs
			STATIC
			${SRCS_LIST_WSM_PCS}
			)

	#生成cmapi库文件
	ADD_LIBRARY ( 
			cmapi
			SHARED
			${SRCS_LIST}
			)

	target_link_libraries(
			cmapi
		
		
			m 
			dl
			${CMAKE_SOURCE_DIR}/bin/libcommon.so
			${CMAKE_SOURCE_DIR}/bin/libchannel.so
			) 


ELSEIF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_WINDOWS}|string>)

	ADD_DEFINITIONS(-DWINDOWS -DWIN32_LEAN_AND_MEAN -DPROTOBUF_USE_DLLS -DCRYPTOKI_EXPORTS -DSM2_WSM) 
	#ADD_DEFINITIONS(-DWINDOWS -DWIN32_LEAN_AND_MEAN -DPROTOBUF_USE_DLLS -DCRYPTOKI_EXPORTS) 
	
	#生成cmapi库文件
	ADD_LIBRARY ( 
			cmapi
			SHARED
			${SRCS_LIST}
			${SRCS_LIST_WSM_PCS}
			)

	target_link_libraries(
			cmapi
		
			common
			channel
			${PROBUFFER_LIB_windows}
			${CMAKE_SOURCE_DIR}/CMApi/CMApi/wsm_pcs/wbcrypto/lib/windows/x86/WhiteBoxCryptoDLL_x86_V0.1.lib
			${CMAKE_SOURCE_DIR}/extern_module/${PLATFORM_LABLE}/${ARCH_LABLE}/pthread/lib/pthreadVC2.lib
			) 
	
ELSEIF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_ANDROID}|string>)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti")

	#生成cmapi库文件
	ADD_LIBRARY ( 
			cmapi
			SHARED
			${SRCS_LIST}
			${SRCS_LIST_WSM_PCS}
			)

	target_link_libraries(
			cmapi
		
			m
			log
			dl
			${CMAKE_SOURCE_DIR}/bin/libcommon.so
			${CMAKE_SOURCE_DIR}/bin/libchannel.so
			${CMAKE_SOURCE_DIR}/CMApi/CMApi/wsm_pcs/protobuf/lib/android/32/libprotobuf.a
			${CMAKE_SOURCE_DIR}/CMApi/CMApi/wsm_pcs/wbcrypto/lib/android/32/libwbcrypto.so
			) 
	
ENDIF()




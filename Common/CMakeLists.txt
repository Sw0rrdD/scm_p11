#添加源文件目录
AUX_SOURCE_DIRECTORY(./src SRCS_LIST)

#工程名称
PROJECT(common)

#头文件搜索路径
INCLUDE_DIRECTORIES(
					${CMAKE_CURRENT_SOURCE_DIR}/include
					
					IF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_WINDOWS}|string>)
						${CMAKE_SOURCE_DIR}/extern_module/${PLATFORM_LABLE}/${ARCH_LABLE}/pthread/include
					ENDIF()
					)

#生成库文件
ADD_LIBRARY ( 
		common
		
		SHARED
		
		${SRCS_LIST})

#针对平台配置
IF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_APPLE}|string>)
	set_target_properties(common PROPERTIES BUILD_WITH_INSTALL_RPATH 1 INSTALL_NAME_DIR "@rpath")
ELSEIF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_UNIX}|string>)
	target_link_libraries(
		common

		rt
		) 
ELSEIF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_WINDOWS}|string>)
	target_link_libraries(
		common

		${CMAKE_SOURCE_DIR}/extern_module/${PLATFORM_LABLE}/${ARCH_LABLE}/pthread/lib/pthreadVC2.lib
		) 
ELSEIF(<${PLATFORM_LABLE}|string> STREQUAL <${PLATFORM_LABLE_ANDROID}|string>)
	target_link_libraries(
		common

		m
		log
		) 
ENDIF()


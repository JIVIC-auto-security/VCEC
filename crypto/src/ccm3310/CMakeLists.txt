cmake_minimum_required(VERSION 3.9) 

project(IDS VERSION 1.0)

SET(CMAKE_SYSTEM_NAME Linux)
SET(TOOLCHAIN_DIR "/opt/fsl-imx-xwayland/5.4-zeus/sysroots/x86_64-pokysdk-linux/usr/usr/bin/aarch64-poky-linux")

SET(CMAKE_FIND_ROOT_PATH "${TOOLCHAIN_DIR}")
SET(CMAKE_C_COMPILER "/opt/fsl-imx-xwayland/5.4-zeus/sysroots/x86_64-pokysdk-linux/usr/bin/aarch64-poky-linux/aarch64-poky-linux-gcc")
SET(CMAKE_CXX_COMPILER "/opt/fsl-imx-xwayland/5.4-zeus/sysroots/x86_64-pokysdk-linux/usr/bin/aarch64-poky-linux/aarch64-poky-linux-g++")

set(MYSYSROOT /opt/fsl-imx-xwayland/5.4-zeus/sysroots/aarch64-poky-linux)

# compiler/linker flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --sysroot=${MYSYSROOT}" CACHE INTERNAL "" FORCE)
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} --sysroot=${MYSYSROOT}" CACHE INTERNAL "" FORCE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --sysroot=${MYSYSROOT}" CACHE INTERNAL "" FORCE)
set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} --sysroot=${MYSYSROOT}" CACHE INTERNAL "" FORCE)

set(CMAKE_FIND_ROOT_PATH "${MYSYSROOT}")

SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
#for libraries and headers in the target directories
#SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
#SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
SET(CMAKE_C_FLAGS"${CMAKE_C_FLAGS} --sysroot=/opt/fsl-imx-xwayland/5.4-zeus/sysroots/aarch64-poky-linux")
SET(CMAKE_CXX_FLAGS"${CMAKE_CXX_FLAGS} --sysroot=/opt/fsl-imx-xwayland/5.4-zeus/sysroots/aarch64-poky-linux")

#SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-lpthread")


add_definitions(-DRPC_OS_LINUX=1)
add_definitions(-DIDSM_OS_LINUX=1)




################# ccm3310s_test ####################
SET(CCM3310STEST_SRC		./src/drivers/drvlib_simos_timer.c				
				./src/drivers/drvlib_led.c
				./src/drivers/drvlib_delay.c											
				./src/drivers/drvlib_gpio.c
				./src/drivers/drvlib_printf.c
				./src/drivers/drvlib_spi.c
				./src/drivers/drvlib_ccm3310s.c				

				./src/ccm3310/crc32.c
				./src/ccm3310/ccm3310s.c				

				./src/app/ccm3310s_test.c) 
						 			  
add_executable(ccm3310 ${CCM3310STEST_SRC})
target_link_libraries(ccm3310 PRIVATE curl pthread)  # add curl lib  ,   pthread lib





#[[
################# led ####################
SET(LED_SRC	./src/drivers/drvlib_simos_timer.c
				./src/drivers/drvlib_led.c				
				./src/apps/led_test.c) 
						 			  
add_executable(ledtest ${LED_SRC})
]]












####################### copy config file #########################




/*****************************************************************************
 ** @FileName drvlib_type.h
 ** @EditBy   PLH
 ** @Version  V0.0.1
 ** @Date     2023-05-29
 ** @brief
*****************************************************************************/
#ifndef _DRVLIB_TYPE_H_
#define _DRVLIB_TYPE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>    ////va_start和va_end 要调用头文件  #include <stdarg.h>     void debug_printf(char* fmt,...)
#include <time.h>
#include <stdbool.h>    // true 1    false 0


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

//uart
#include <signal.h>
#include <termios.h>

//key
#include <linux/input.h>

//SPI
#include <linux/spi/spidev.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//net
#include <curl/curl.h>   //curl 第三方开源库,要求ARM板中要装有这个库
#include <netdb.h>
#include <arpa/inet.h>



//can
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <linux/can/error.h>


//tcp socket
#include <sys/shm.h>


#define UDS_OS_LINUX
//#define UDS_OS_WINDOWS



//#include "S32K144.h"	

#define MY_TRUE	   0
#define MY_FALSE 	 1

#define RET_TRUE	   0
#define RET_FALSE 	 1

typedef unsigned char   RET_BOOL;


typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;




typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;


typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;


//#if(DEBUG_APP_UDS == 1)		
//DEBUG("\r\n chassis can2 receive data \r\n");
//#endif	







#endif

/************************ END OF THIS FILE ************************/


/**
* @file        drvlib_spi.h
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#ifndef _DRVLIB_SPI_H_
#define _DRVLIB_SPI_H_

#include "drvlib_type.h"
#include "drvlib_printf.h"


#define spi_DEV_path        "/dev/spidev1.0"

/*SPI 接收 、发送 缓冲区*/
extern unsigned char tx_buffer[200];
extern unsigned char rx_buffer[200];

extern int spifd;                          // SPI 控制引脚的设备文件描述符

//spi初始化
int spi_init(void);

//spi发送数据
int transfer(int fd, uint8_t const* tx, uint8_t const* rx, size_t len);




	 				    
#endif

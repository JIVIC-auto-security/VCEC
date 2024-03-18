/**
* @file        drvlib_ccm3310s.h
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#ifndef _DRVLIB_CCM3310S_H_
#define _DRVLIB_CCM3310S_H_

#include "drvlib_type.h"
#include "drvlib_printf.h"
#include "drvlib_spi.h"
#include "drvlib_gpio.h"




void ccm3310s_Init(void);


uint8_t ccm3310s_Check_Ready(void);

	 				    
#endif

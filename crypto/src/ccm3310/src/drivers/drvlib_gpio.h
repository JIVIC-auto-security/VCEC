/**
* @file        drvlib_gpio.h
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#ifndef _DRVLIB_GPIO_H_
#define _DRVLIB_GPIO_H_

#include "drvlib_type.h"

#define  RB_PIN_GPIO_NUM    "10"      //板上丝印RST


extern char gpio_path[100];

extern int RB_fd;



int config_RB_GPIO(void);

int getGpioValue();
	 				    
#endif

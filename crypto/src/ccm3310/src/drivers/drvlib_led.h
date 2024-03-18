/**
* @file        drvlib_led.h
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#ifndef _DRVLIB_LED_H_
#define _DRVLIB_LED_H_

#include "drvlib_type.h"


#define  LED_ON    1
#define  LED_OFF   0


extern uint8_t RunLED_state;
extern uint8_t GNSSLED_state;

void led_init(void);

void LED_RUN(uint8_t led_state);

void LED_NET(uint8_t led_state);
	 				    
#endif

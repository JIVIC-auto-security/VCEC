/**
* @file        basic.h
* @brief       Basic_operations
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/

#ifndef __BASIC_H_
#define __BASIC_H_ 	

#include "../drivers/drvlib.h"
#include "com.h"

extern uint8_t chip_SN[16];



void ccm3310s_GetVersion(void);
void ccm3310s_GetSN(uint8_t* outputSN);


void ccm3310s_GetRandom(void);



#endif






























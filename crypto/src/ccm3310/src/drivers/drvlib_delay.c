/**
* @file        drvlib_delay.c
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "drvlib_delay.h"

void delay_ms(uint32_t nms)
{
  usleep(nms * 1000);   //1ms
}










































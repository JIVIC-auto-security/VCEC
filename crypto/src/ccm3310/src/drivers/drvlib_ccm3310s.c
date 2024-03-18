/**
* @file        drvlib_ccm3310s.h
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "drvlib_ccm3310s.h"





void ccm3310s_Init(void)
{
  int ret;

  ret = spi_init();
  if (-1 == ret)
  {
    DEBUG("spi_init error\n");    
  }

  //read rb pin config
  config_RB_GPIO();
  getGpioValue();

  DEBUG("ccm3310s_Init finish\n");
}






//0  ready
//1  busy
//   Timeout 2S
//wait reply, check RB pin
uint8_t ccm3310s_Check_Ready(void)
{
  uint32_t i;
  uint32_t Timeout = 1000;   //1ms*1000 =1000ms=1s  Timeout

  //check RB pin
  for (i = 0; i < Timeout; i++)
  {
    if (getGpioValue() == 0)  //0 ready
    {
      delay_ms(5);					   //防抖  发现SM2验签存在引脚输出抖动，加上这					 

      if (getGpioValue() == 0)
      {
        //        	DEBUG("chip  ready \r\n");
        usleep(2000);   //2ms  //实际调试,检测到引脚低电平后还要稍微等1,2ms一下，芯片才真正达到可工作状态			

        return RET_TRUE;
      }
    }
    else    //1  busy
    {
      usleep(1000);   //1ms
      //        	DEBUG("chip  busy \r\n");
    }
  }

  DEBUG("encrypt chip timeout! \r\n");

  return RET_FALSE;
}



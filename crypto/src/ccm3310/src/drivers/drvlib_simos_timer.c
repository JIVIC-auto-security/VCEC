/*****************************************************************************
 ** @FileName drvlib_simos_timer.c
 ** @EditBy   Larry Pang
 ** @Version V1.0
 ** @Date     2023-06-09
 ** @brief    TIMER2 as Os timer
*****************************************************************************/

#include "drvlib_simos_timer.h"

volatile unsigned timerTick = 0x00;

void simOs_timConfiguration(void)
{
	
}



unsigned simOs_getCurrentTime(void)
{
	return timerTick;
}


unsigned char simOs_checkTimeout(unsigned timStart, unsigned timNow, unsigned timOut)
{
	#define activateCNT ((unsigned)(timOut+timStart))

	if( timOut==0 )
	{
		return 0x01;
	}
	if (activateCNT > timStart)//start+timout is not overflow
	{
		if ((timNow >= activateCNT) || (timNow < timStart))
		{
			return 0x01;
		}
	}
	else if ( (timNow >= activateCNT) && (timNow < timStart) ) //start+timout is overflow
	{
		return 0x01;
	}
	
	return 0x00;
}


//对main中usleep 计数
void OS_TimerCount(void)
{
  timerTick++;
}






/************************ END OF THIS FILE ************************/

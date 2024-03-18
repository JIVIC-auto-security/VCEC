/*****************************************************************************
 ** @FileName drvlib_simos_timer.h
 ** @EditBy   Larry Pang
 ** @Version  V1.0
 ** @Date     2023-06-09
 ** @brief
*****************************************************************************/

#ifndef _DRVLIB_SIMOS_TIMER_H_
#define _DRVLIB_SIMOS_TIMER_H_


#define OS_TIMER_CYCLE   1  //1ms

extern volatile unsigned timerTick;

void simOs_timConfiguration(void);
unsigned simOs_getCurrentTime(void);
unsigned char simOs_checkTimeout(unsigned timStart, unsigned timNow, unsigned timOut);



void OS_TimerCount(void);


#endif

/************************ END OF THIS FILE ************************/


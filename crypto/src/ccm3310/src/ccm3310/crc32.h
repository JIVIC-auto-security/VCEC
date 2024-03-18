/*****************************************************************************
 ** @FileName crc32.h
 ** @EditBy   PLH
 ** @Version  V0.0.1
 ** @Date     2023-10-08
 ** @brief    
*****************************************************************************/
#ifndef _CRC32_H_
#define _CRC32_H_

#include "../drivers/drvlib.h"


extern uint32_t m_flashCrc32Value;

void UdsCrc32Init(void);


void Caculate_FW_CRC(void* input, int len);

uint32_t crc32(uint32_t crc, void* input, int len);

#endif

/************************ END OF THIS FILE ************************/

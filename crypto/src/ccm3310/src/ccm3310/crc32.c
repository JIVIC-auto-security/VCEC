/*****************************************************************************
 ** @FileName crc32.c
 ** @EditBy   plh
 ** @Version  V0.0.1
 ** @Date     2023-10-08
 ** @brief    
*****************************************************************************/
#include "crc32.h"



uint32_t m_flashCrc32Value;

uint32_t m_Crc32table[256];


/*******crc32 calculate variable *******************************/
uint32_t m_Crc32InitValue = 0xFFFFFFFF;
static uint32_t m_Crc32PolyValue = 0x04C11DB7;


void Caculate_FW_CRC(void* input, int len)
{
  m_flashCrc32Value = m_Crc32InitValue;
  
  m_flashCrc32Value = crc32(m_flashCrc32Value, input, len);

  m_flashCrc32Value ^= 0xFFFFFFFFF; // 这步也要才是最终输出的CRC值

  printf("CRC value 0x%X \n", m_flashCrc32Value);
}


//???  
static uint32_t bitrev(unsigned long input, int bw)
{
  int i;
  unsigned long var;
  var = 0;
  for (i = 0; i < bw; i++)
  {
    if (input & 0x01)
    {
      var |= 1 << (bw - 1 - i);
    }
    input >>= 1;
  }
  return var;
}

//????  
//?:X32+X26+...X1+1,poly=(1<<26)|...|(1<<1)|(1<<0)  
void crc32_initTable(uint32_t poly)
{
  int32_t i;
  int32_t j;
  uint32_t c;

  poly = bitrev(poly, 32);
  for (i = 0; i < 256; i++)
  {
    c = i;
    for (j = 0; j < 8; j++)
    {
      if (c & 1)
      {
        c = poly ^ (c >> 1);
      }
      else
      {
        c = c >> 1;
      }
    }
    m_Crc32table[i] = c;
  }
}

uint32_t crc32(uint32_t crc, void* input, int len)
{
  int i;
  uint8_t index;
  uint8_t* pch;
  pch = (uint8_t*)input;
  for (i = 0; i < len; i++)
  {
    index = (unsigned char)(crc ^ *pch);
    crc = (crc >> 8) ^ m_Crc32table[index];
    pch++;
  }
  return crc;
}

void UdsCrc32Init(void)
{
  m_flashCrc32Value = m_Crc32InitValue;
  crc32_initTable(m_Crc32PolyValue);
}



/************************ END OF THIS FILE ************************/


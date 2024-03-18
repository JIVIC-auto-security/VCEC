/**
* @file        com.c
* @brief       common functions
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "com.h"

uint8_t ins;     //function ID  (only part)

uint8_t CCM3310_WriteBuf[4096];    // send the data to ccm3310
uint8_t FILLBuf[4096] = { 0 };    // send the data to ccm3310
uint8_t CCM3310_ReadBuf[1024];    // receive the data from ccm3310


void Write_analyse(void)
{
  uint8_t i;
  uint16_t cnt = 0;

  printf("\n ------------------------------------------- \n");

  if (ins == GetVersion_INS)
    printf("get version");
  else if (ins == GetSN_INS)
    printf("GetSN");
  else if (ins == GetRandom_INS)
    printf("GetRandom");
  else if (ins == Hash_Init_INS)
    printf("Hash_Init");
  else if (ins == Hash_Update_INS)
    printf("Hash_Update\r\n");
  else if (ins == Hash_Final_INS)
    printf("Hash_Final\n");


  printf(" send data:\r\n");


  uint32_t length;
  uint16_t LO_WORD_len, HI_WORD_len;

  //-----------------------------------------//
  LO_WORD_len = MAKE_WORD(CCM3310_WriteBuf[4], CCM3310_WriteBuf[5]);
  HI_WORD_len = MAKE_WORD(CCM3310_WriteBuf[6], CCM3310_WriteBuf[7]);
  length = MAKE_LONG(LO_WORD_len, HI_WORD_len);
  //-----------------------------------------//

  printf("包头占固定4字节: \t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }
  printf("\r\n");

  printf("数据长度占4字节 \t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }

  printf("// %d 个字节 \r\n", length);

  printf("命令字段占4字节: \t\t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }
  printf("\r\n");

  printf("保留字段占4字节: \t\t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }
  printf("\r\n");

  //----------------------------------------------//
  if (CCM3310_WriteBuf[9] == 0x48)  //hash init
  {
    printf("无数据区:	\r\n");
  }
  else if (CCM3310_WriteBuf[9] == 0x4A)  //hash update
  {
    printf("数据部分:	\r\n");

    printf("已处理长度:	\r\n");
    for (i = 0; i < 8; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("中间值32个字节:	\r\n");
    for (i = 0; i < 32; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("Hash 输入消息值:	\r\n");
    for (i = 0; i < (length - 8 - 32); i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");
  }
  else if (CCM3310_WriteBuf[9] == 0x4C)  //hash Final
  {
    printf("数据部分:	\r\n");

    printf("已处理长度:	\r\n");
    for (i = 0; i < 8; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("中间值32个字节:	\r\n");
    for (i = 0; i < 32; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("Hash 输入最后一包消息值:	\r\n");
    for (i = 0; i < (length - 8 - 32); i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");
  }
  else if (CCM3310_WriteBuf[9] == 0x4E)  //hash onece
  {
    printf("传入消息数据:	\r\n");

    for (i = 0; i < length; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");
  }
  else
  {
    /*	printf("数据部分:	\r\n");

      printf("私钥:	\r\n");
      for(i=0;i<32;i++)
      {
        printf("%02X ",CCM3310_WriteBuf[cnt]);
        cnt++;
      }
      printf("\r\n");

      printf("随机数:	\r\n");
      for(i=0;i<32;i++)
      {
        printf("%02X ",CCM3310_WriteBuf[cnt]);
        cnt++;
      }
      printf("\r\n");

      printf("签名数据固定32个字节:	\r\n");
      for(i=0;i<32;i++)
      {
        printf("%02X ",CCM3310_WriteBuf[cnt]);
        cnt++;
      }
      printf("\r\n");*/

      //orignal data
    //	for(i=0;i<length;i++)
    //	{
    //		printf("%02X ",CCM3310_WriteBuf[cnt]);
    //		cnt++;
    //	}
    printf("\r\n");

  }



  //----------------------------------------------//

  printf("下行包尾固定4字节: \t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }
  printf("\r\n");
}


void Read_analyse(void)
{
  uint8_t i;
  uint16_t cnt = 0;

  uint32_t length;

  DEBUG("Read_analyse start-------------------------------------- \r\n");

  if (ins == GetVersion_INS)
    printf("get version");
  else if (ins == GetSN_INS)
    printf("GetSN");
  else if (ins == GetRandom_INS)
    printf("GetRandom");
  else if (ins == Hash_Init_INS)
    printf("Hash_Init");
  else if (ins == Hash_Update_INS)
    printf("Hash_Update\r\n");
  else if (ins == Hash_Final_INS)
    printf("Hash_Final\r\n");
  else if (ins == Hash_Final_INS)
    printf("Hash_Final\r\n");
  else if (ins == Hash_Once_INS)
    printf("Hash_Once\r\n");
  else if (ins == SM2_Calc_Z_INS)
    printf("SM2_Calc_Z\r\n");
  else if (ins == SM2_Verify_INS)
    printf("SM2_Verify\r\n");

  printf(" replay data:\r\n");

  DEBUG("head 4B: \t");
  for (i = 0; i < 4; i++)
  {
    DEBUG("%02X ", CCM3310_ReadBuf[cnt]);
    cnt++;
  }
  DEBUG("\r\n");

  DEBUG("data len 4B \t");
  for (i = 0; i < 4; i++)
  {
    DEBUG("%02X ", CCM3310_ReadBuf[cnt]);
    cnt++;
  }

  length = CCM3310_ReadBuf[4];  //这样写有问题，回复数据超过256 就不能这样写！！！

  DEBUG("// %d B \r\n", length);

  //--------------------------------------------------------------------------------------//
  DEBUG("state 2B: ");
  for (i = 0; i < 2; i++)
  {
    DEBUG("%02X ", CCM3310_ReadBuf[cnt]);
    cnt++;
  }

  //判断状态字
  if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x90) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x00))   //90 00   正确执行
  {
    DEBUG(" // exe correct\r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x6A) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x8C))   //6A 8C 密钥id 对应的密钥不存在
  {
    DEBUG(" //key miss in select key_address  \r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x69) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x89))   //69 89 随机数缺失或长度错误
  {
    DEBUG(" //random miss or wrong  \r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x6A) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x80))   //6A 80   正确执行
  {
    DEBUG(" // data parameter wrong\r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x90) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x86))   //90 86   正确执行
  {
    DEBUG(" // SM2 verify wrong\r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x67) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x00))   //67 00  数据长度错误
  {
    DEBUG(" // data len wrong \r\n");
  }
  else
  {
    DEBUG(" // unknow \r\n");
  }
  //--------------------------------------------------------------------------------------//

  DEBUG("reserved 6B: \t\t");
  for (i = 0; i < 6; i++)
  {
    DEBUG("%02X ", CCM3310_ReadBuf[cnt]);
    cnt++;
  }
  DEBUG("\r\n");

  DEBUG("data part:	\r\n");

  if (ins == GetVersion_INS)
  {
    for (i = 0; i < length; i++)
    {
      DEBUG("%c", CCM3310_ReadBuf[cnt]);
      cnt++;
    }
    DEBUG("\r\n");

  }
  else
  {
    for (i = 0; i < length; i++)
    {
      DEBUG("%02X ", CCM3310_ReadBuf[cnt]);
      cnt++;
    }
    DEBUG("\r\n");
  }


  DEBUG("tail 4B: \t");
  for (i = 0; i < 4; i++)
  {
    DEBUG("%02X ", CCM3310_ReadBuf[cnt]);
    cnt++;
  }
  DEBUG("\r\n");

  DEBUG("Read_analyse end-------------------------------------- \r\n");
}









































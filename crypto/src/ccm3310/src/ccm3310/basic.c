/**
* @file        basic.c
* @brief        Basic_operations
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "basic.h"





/*
函数功能：读取芯片的版本号
*/
void ccm3310s_GetVersion(void)
{
  uint8_t cnt = 0;
  uint8_t ret = 0;

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = GetVersion_INS;
  //---------------------------------//
  //head
  CCM3310_WriteBuf[cnt++] = 0x53;
  CCM3310_WriteBuf[cnt++] = 0x02;
  CCM3310_WriteBuf[cnt++] = 0x10;
  CCM3310_WriteBuf[cnt++] = 0x33;

  //length
  CCM3310_WriteBuf[cnt++] = 0x50;
  CCM3310_WriteBuf[cnt++] = 0x00;
  CCM3310_WriteBuf[cnt++] = 0x00;
  CCM3310_WriteBuf[cnt++] = 0x00;

  ////cmd
  CCM3310_WriteBuf[cnt++] = 0x80; //CLA
  CCM3310_WriteBuf[cnt++] = GetVersion_INS;  //INS
  CCM3310_WriteBuf[cnt++] = 0x00;
  CCM3310_WriteBuf[cnt++] = 0x00;

  //reserve
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x55;

  //tail
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x02;
  CCM3310_WriteBuf[cnt++] = 0x33;
  CCM3310_WriteBuf[cnt++] = 0x01;

  ret = transfer(spifd, CCM3310_WriteBuf, CCM3310_ReadBuf, cnt);
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }

  ///*打印  CCM3310_ReadBuf   无意义的数据*/
  //printf("CCM3310_ReadBuf size %d:\n ", cnt);
  //for (int i = 0; i < cnt; i++)    //read bytes!
  //{
  //  printf(" %02X ", CCM3310_ReadBuf[i]);
  //}
  //printf("\r\n ");

  //----------------------------------------------------------------//
#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#else
  usleep(200000);  //200ms
#endif      

  //read
  //DEBUG("spi read \r\n ");
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 80 + 4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//

  Write_analyse();

  Read_analyse();

}


/*
函数功能：读取芯片的序列号
*/
void ccm3310s_GetSN(uint8_t* outputSN)
{
  uint8_t cnt = 0;
  uint8_t ret = 0;
  uint32_t i = 0;

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = GetSN_INS;
  //---------------------------------//
  //head
  CCM3310_WriteBuf[cnt++] = 0x53;
  CCM3310_WriteBuf[cnt++] = 0x02;
  CCM3310_WriteBuf[cnt++] = 0x10;
  CCM3310_WriteBuf[cnt++] = 0x33;

  //length
  CCM3310_WriteBuf[cnt++] = 0x10;
  CCM3310_WriteBuf[cnt++] = 0x00;
  CCM3310_WriteBuf[cnt++] = 0x00;
  CCM3310_WriteBuf[cnt++] = 0x00;

  ////cmd
  CCM3310_WriteBuf[cnt++] = 0x80; //CLA
  CCM3310_WriteBuf[cnt++] = GetSN_INS;  //INS
  CCM3310_WriteBuf[cnt++] = 0x00;
  CCM3310_WriteBuf[cnt++] = 0x00;

  //reserve
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x55;

  //tail
  CCM3310_WriteBuf[cnt++] = 0x55;
  CCM3310_WriteBuf[cnt++] = 0x02;
  CCM3310_WriteBuf[cnt++] = 0x33;
  CCM3310_WriteBuf[cnt++] = 0x01;

  ret = transfer(spifd, CCM3310_WriteBuf, CCM3310_ReadBuf, cnt);
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }

  //----------------------------------------------------------------//
#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#else
  usleep(200000);  //200ms
#endif      

  //read  
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 16 + 4));
  if (-1 == ret)
  {
    printf(" spi transfer error...\n");
  }
  //-------------------------------------------------//

  //read
  for (i = 0; i < 16; i++)    //read bytes!
  {
  }

  for (i = 0; i < 16; i++)    //sn
  {
    outputSN[i] = CCM3310_ReadBuf[16 + i];   //save sn value
  }

  for (i = 0; i < 4; i++)    //read bytes!
  {
  }

  //Write_analyse();

  //Read_analyse();

}




void ccm3310s_GetRandom(void)
{
  uint8_t cnt = 0;
  uint8_t ret = 0;

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = GetRandom_INS;

  //head
  CCM3310_WriteBuf[cnt++] = (0x53);
  CCM3310_WriteBuf[cnt++] = (0x02);
  CCM3310_WriteBuf[cnt++] = (0x10);
  CCM3310_WriteBuf[cnt++] = (0x33);

  //length
  CCM3310_WriteBuf[cnt++] = (0x04);  //请求4个字节
  CCM3310_WriteBuf[cnt++] = (0x00);
  CCM3310_WriteBuf[cnt++] = (0x00);
  CCM3310_WriteBuf[cnt++] = (0x00);

  //cmd
  CCM3310_WriteBuf[cnt++] = (0x80);   //CLA
  CCM3310_WriteBuf[cnt++] = GetRandom_INS;   //INS
  CCM3310_WriteBuf[cnt++] = (0x00);
  CCM3310_WriteBuf[cnt++] = (0x00);

  //reserve
  CCM3310_WriteBuf[cnt++] = (0x55);
  CCM3310_WriteBuf[cnt++] = (0x55);
  CCM3310_WriteBuf[cnt++] = (0x55);
  CCM3310_WriteBuf[cnt++] = (0x55);

  //tail
  CCM3310_WriteBuf[cnt++] = (0x55);
  CCM3310_WriteBuf[cnt++] = (0x02);
  CCM3310_WriteBuf[cnt++] = (0x33);
  CCM3310_WriteBuf[cnt++] = (0x01);

  ret = transfer(spifd, CCM3310_WriteBuf, CCM3310_ReadBuf, cnt);
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //----------------------------------------------------------------//
#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#else
  usleep(200000);  //200ms
#endif      

  //read  
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, 24);
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//
  Write_analyse();
  Read_analyse();
}





































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

  printf("��ͷռ�̶�4�ֽ�: \t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }
  printf("\r\n");

  printf("���ݳ���ռ4�ֽ� \t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }

  printf("// %d ���ֽ� \r\n", length);

  printf("�����ֶ�ռ4�ֽ�: \t\t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }
  printf("\r\n");

  printf("�����ֶ�ռ4�ֽ�: \t\t");
  for (i = 0; i < 4; i++)
  {
    printf("%02X ", CCM3310_WriteBuf[cnt]);
    cnt++;
  }
  printf("\r\n");

  //----------------------------------------------//
  if (CCM3310_WriteBuf[9] == 0x48)  //hash init
  {
    printf("��������:	\r\n");
  }
  else if (CCM3310_WriteBuf[9] == 0x4A)  //hash update
  {
    printf("���ݲ���:	\r\n");

    printf("�Ѵ�����:	\r\n");
    for (i = 0; i < 8; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("�м�ֵ32���ֽ�:	\r\n");
    for (i = 0; i < 32; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("Hash ������Ϣֵ:	\r\n");
    for (i = 0; i < (length - 8 - 32); i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");
  }
  else if (CCM3310_WriteBuf[9] == 0x4C)  //hash Final
  {
    printf("���ݲ���:	\r\n");

    printf("�Ѵ�����:	\r\n");
    for (i = 0; i < 8; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("�м�ֵ32���ֽ�:	\r\n");
    for (i = 0; i < 32; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");

    printf("Hash �������һ����Ϣֵ:	\r\n");
    for (i = 0; i < (length - 8 - 32); i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");
  }
  else if (CCM3310_WriteBuf[9] == 0x4E)  //hash onece
  {
    printf("������Ϣ����:	\r\n");

    for (i = 0; i < length; i++)
    {
      printf("%02X ", CCM3310_WriteBuf[cnt]);
      cnt++;
    }
    printf("\r\n");
  }
  else
  {
    /*	printf("���ݲ���:	\r\n");

      printf("˽Կ:	\r\n");
      for(i=0;i<32;i++)
      {
        printf("%02X ",CCM3310_WriteBuf[cnt]);
        cnt++;
      }
      printf("\r\n");

      printf("�����:	\r\n");
      for(i=0;i<32;i++)
      {
        printf("%02X ",CCM3310_WriteBuf[cnt]);
        cnt++;
      }
      printf("\r\n");

      printf("ǩ�����ݹ̶�32���ֽ�:	\r\n");
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

  printf("���а�β�̶�4�ֽ�: \t");
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

  length = CCM3310_ReadBuf[4];  //����д�����⣬�ظ����ݳ���256 �Ͳ�������д������

  DEBUG("// %d B \r\n", length);

  //--------------------------------------------------------------------------------------//
  DEBUG("state 2B: ");
  for (i = 0; i < 2; i++)
  {
    DEBUG("%02X ", CCM3310_ReadBuf[cnt]);
    cnt++;
  }

  //�ж�״̬��
  if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x90) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x00))   //90 00   ��ȷִ��
  {
    DEBUG(" // exe correct\r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x6A) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x8C))   //6A 8C ��Կid ��Ӧ����Կ������
  {
    DEBUG(" //key miss in select key_address  \r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x69) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x89))   //69 89 �����ȱʧ�򳤶ȴ���
  {
    DEBUG(" //random miss or wrong  \r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x6A) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x80))   //6A 80   ��ȷִ��
  {
    DEBUG(" // data parameter wrong\r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x90) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x86))   //90 86   ��ȷִ��
  {
    DEBUG(" // SM2 verify wrong\r\n");
  }
  else if ((CCM3310_ReadBuf[STATE_OK_HB_P] == 0x67) && (CCM3310_ReadBuf[STATE_OK_LB_P] == 0x00))   //67 00  ���ݳ��ȴ���
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









































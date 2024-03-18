/**
* @file        ccm3310s.c
* @brief       chip:   国芯加密芯片CCM3310S-T 应用层协议
* @details
* @author
* @date
* @version     V1.0
*  Version:  V0.1.4   update 221208
*   V0.1.3   write My_SM2_Calc_HASH input message can >128 ;    ccm3310s_Check_Ready 加入防抖
    uint8_t Hash_Final(uint8_t P1,uint8_t* message, uint32_t message_len,uint8_t* OutPut_Hash)  修改传出参数
    void Hash_Package(uint8_t* Input_Message, uint32_t Package_Len,uint32_t Each_hash_Len,uint8_t* OutPut_Hash);    修改传出参数
    void SM2_Calc_Z(uint8_t Key_ID, uint8_t* OutPut_Z)      IDA data 用的是国标的的IDA!!!!!!!!!!!!!!!!!!!!!
* @par Copyright(c):
*/


#include "ccm3310s.h"

uint8_t CCM3310_WriteBuf[4096];    // send the data to ccm3310
uint8_t FILLBuf[4096] = {0};    // send the data to ccm3310
uint8_t CCM3310_ReadBuf[1024];    // receive the data from ccm3310

uint8_t ins;     //function ID  (only part)


//-------------------------------------------------------------------------------------------------//
//国标文档中的示范值
//32 Bytes
const uint8_t Known_SM2_Private_Key[32] =
{
		//国标示例中
		0x39,0x45,0x20,0x8F,0x7B,0x21,0x44,0xB1,0x3F,0x36,0xE3,0x8A,0xC6,0xD3,0x9F,0x95,
		0x88,0x93,0x93,0x69,0x28,0x60,0xB5,0x1A,0x42,0xFB,0x81,0xEF,0x4D,0xF7,0xC5,0xB8
};

//64 Bytes
const uint8_t Known_SM2_Public_Key[64] =
{
		//国标示例中
		0x09,0xF9,0xDF,0x31,0x1E,0x54,0x21,0xA1,0x50,0xDD,0x7D,0x16,0x1E,0x4B,0xC5,0xC6,
		0x72,0x17,0x9F,0xAD,0x18,0x33,0xFC,0x07,0x6B,0xB0,0x8F,0xF3,0x56,0xF3,0x50,0x20,
		0xCC,0xEA,0x49,0x0C,0xE2,0x67,0x75,0xA5,0x2D,0xC6,0xEA,0x71,0x8C,0xC1,0xAA,0x60,
		0x0A,0xED,0x05,0xFB,0xF3,0x5E,0x08,0x4A,0x66,0x32,0xF6,0x07,0x2D,0xA9,0xAD,0x13
};


//6D 65 73 73 61 67 65 20 64 69 67 65 73 74    //message digest  	中间有空格，转成16进制
const uint8_t Know_Message[14] =
{
   //国标中的文档 示范值
  'm', 'e', 's', 's', 'a', 'g', 'e', ' ', 'd', 'i', 'g', 'e', 's', 't'
};

//这边随机数应该做了预处理，和国标文档里面带入的入口阶段不一样
const uint8_t Known_Random[] = //这里应该不用-1 和stm32 不一样
{
	//国标示例中
	0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D,0xCC,
	0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21
};


//对原始数据 hash后的计算值
const uint8_t Known_Hash[32] =
{
	//国标中的文档 hash值
	0xF0,0xB4,0x3E,0x94,0xBA,0x45,0xAC,0xCA,0xAC,0xE6,0x92,0xED,0x53,0x43,0x82,0xEB,
	0x17,0xE6,0xAB,0x5A,0x19,0xCE,0x7B,0x31,0xF4,0x48,0x6F,0xDF,0xC0,0xD2,0x86,0x40
};

//64个字节
const uint8_t Known_Signature[64] =
{
	//国标中的文档
	0xF5,0xA0,0x3B,0x06,0x48,0xD2,0xC4,0x63,0x0E,0xEA,0xC5,0x13,0xE1,0xBB,0x81,0xA1,
	0x59,0x44,0xDA,0x38,0x27,0xD5,0xB7,0x41,0x43,0xAC,0x7E,0xAC,0xEE,0xE7,0x20,0xB3,
	0xB1,0xB6,0xAA,0x29,0xDF,0x21,0x2F,0xD8,0x76,0x31,0x82,0xBC,0x0D,0x42,0x1C,0xA1,
	0xBB,0x90,0x38,0xFD,0x1F,0x7F,0x42,0xD4,0x84,0x0B,0x69,0xC4,0x85,0xBB,0xC1,0xAA
};

//-----------------------------------------------//


//64 Bytes
//16 进制 828A5C4F3B29B120E182FE3CC09EA2ECDE118CE6A14C47D54E24F793A4D95318D4555303CCB413C6577170E64B8FE2F60C20C60E47FED647713111744B8102F1
const uint8_t Known_Service_SM2_Public_Key[64] =
{
  0x82,0x8A,0x5C,0x4F,0x3B,0x29,0xB1,0x20,0xE1,0x82,0xFE,0x3C,0xC0,0x9E,0xA2,0xEC,
  0xDE,0x11,0x8C,0xE6,0xA1,0x4C,0x47,0xD5,0x4E,0x24,0xF7,0x93,0xA4,0xD9,0x53,0x18,
  0xD4,0x55,0x53,0x03,0xCC,0xB4,0x13,0xC6,0x57,0x71,0x70,0xE6,0x4B,0x8F,0xE2,0xF6,
  0x0C,0x20,0xC6,0x0E,0x47,0xFE,0xD6,0x47,0x71,0x31,0x11,0x74,0x4B,0x81,0x02,0xF1
};


//-------------------------------------------------------------------------------------------------//



//32 Bytes
const uint8_t Private_Key[] =
{
//		//TBOX端
//		0x6C, 0xB2, 0x8D, 0x99, 0x38, 0x5C, 0x17, 0x5C, 0x94, 0xF9, 0x4E, 0x93, 0x48, 0x17, 0x66, 0x3F,
//		0xC1, 0x76, 0xD9, 0x25, 0xDD, 0x72, 0xB7, 0x27, 0x26, 0x0D, 0xBA, 0xAE, 0x1F, 0xB2, 0xF9, 0x6F

		//国标示例中
		0x39,0x45,0x20,0x8F,0x7B,0x21,0x44,0xB1,0x3F,0x36,0xE3,0x8A,0xC6,0xD3,0x9F,0x95,
		0x88,0x93,0x93,0x69,0x28,0x60,0xB5,0x1A,0x42,0xFB,0x81,0xEF,0x4D,0xF7,0xC5,0xB8
};

//64 Bytes
const uint8_t Public_Key[] =
{
//		//TBOX端
//		0xF6, 0xA6, 0x87, 0xAB, 0x57, 0x44, 0xD5, 0xCB, 0xBA, 0x1C, 0xF9, 0x3D, 0x84, 0x36, 0x41, 0x6F,
//		0x75, 0xC3, 0xAE, 0xC3, 0xD7, 0x62, 0x81, 0x4D, 0x56, 0x53, 0x14, 0xAF, 0xF5, 0x7A, 0x89, 0xF9,
//		0xF1, 0xB8, 0xEE, 0x05, 0x41, 0x74, 0x05, 0x65, 0x49, 0x1E, 0x44, 0x04, 0x3D, 0xE5, 0x3C, 0xF5,
//		0xBB, 0xED, 0xD6, 0x13, 0x33, 0x07, 0x12, 0x60, 0xDF, 0xC5, 0x78, 0x3F, 0x47, 0xA7, 0xB9, 0x81

		//国标示例中
		0x09,0xF9,0xDF,0x31,0x1E,0x54,0x21,0xA1,0x50,0xDD,0x7D,0x16,0x1E,0x4B,0xC5,0xC6,
		0x72,0x17,0x9F,0xAD,0x18,0x33,0xFC,0x07,0x6B,0xB0,0x8F,0xF3,0x56,0xF3,0x50,0x20,
		0xCC,0xEA,0x49,0x0C,0xE2,0x67,0x75,0xA5,0x2D,0xC6,0xEA,0x71,0x8C,0xC1,0xAA,0x60,
		0x0A,0xED,0x05,0xFB,0xF3,0x5E,0x08,0x4A,0x66,0x32,0xF6,0x07,0x2D,0xA9,0xAD,0x13
};

//签名原始数据的 大小应不超过 128byte
uint8_t Message[MESSAGE_SIZE];    //Know_Message

//对原始数据 hash后的计算值
uint8_t Computed_Hash[32];

//计算出的Z值
uint8_t Computed_Z[32];


uint8_t Computed_Signature[64];


const uint8_t Test_Hash[32] =
{
    //元数据的签名值
		0x98, 0xCE, 0x42, 0xDE, 0xEF, 0x51, 0xD4, 0x02, 0x69, 0xD5, 0x42, 0xF5, 0x31, 0x4B, 0xEF,
		0x2C, 0x74, 0x68, 0xD4, 0x01, 0xAD, 0x5D, 0x85, 0x16, 0x8B, 0xFA, 0xB4, 0xC0

};

const uint8_t Test_Signature[64] =
{
    //元数据的签名值
		0xC4, 0x8E, 0x40, 0x23, 0xAE, 0x84, 0xBD, 0x73, 0x19, 0x68, 0xE9, 0xB2, 0x61, 0xE6, 0xC5,
		0x93, 0x19, 0x64, 0xE7, 0xB0, 0x4D, 0x13, 0x73, 0x07, 0xB9, 0xDD, 0xA0, 0x34, 0x8F, 0x22,
		0x60, 0xE6, 0xC0, 0x43, 0xC9, 0xB9, 0x1A, 0x4A, 0xD3, 0x40, 0x35, 0x13, 0x87, 0x52, 0x10,
		0x89, 0x04, 0x3F, 0xCF, 0x69, 0xD8, 0xC7, 0xF8, 0x64, 0xAA, 0x71, 0xD5, 0x02, 0x69, 0xBF,
		0xA2, 0xD4, 0x38, 0xCA,

};

uint8_t Computed_EncryptData[200]; //only for test






//Hash use
uint8_t BLOCK_len;
uint8_t Processed_Buf[8];
uint8_t Median_Buf[32];

//----------------------------------------------------------------------//

/*
函数功能：SPI读写一个字节
  CPOL = 1, CPHA = 1, MSB first
*/
static u8 SPI_ReadWriteOneByte(u8 data_tx)
{
	u8 data_rx=0; //存放读取的数据



	return data_rx;
}

//----------------------------------------------------//



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
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, 24 );
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//
  Write_analyse();
  Read_analyse();
}

//P1 选着算法
//杂凑算法： 0x00 SM3 ）、 0x01 SHA0 ）、0x02 SHA1 ）、 0x03 SHA224 ）、 0x04 SHA256
// pro_Buf  传出已处理长度
// med_Buf  传出中间值
// 返回值      1 正确执行   0 错误
uint8_t Hash_Init(uint8_t P1,uint8_t* p_BLOCK_len ,uint8_t* pro_Buf ,uint8_t* med_Buf)
{	
  uint8_t cnt = 0;
  uint8_t ret = 0;
  int i = 0;

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif	

  ins = Hash_Init_INS;

	//head
	CCM3310_WriteBuf[cnt++] = 0x53;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x10;
	CCM3310_WriteBuf[cnt++] = 0x33;

	//length
	CCM3310_WriteBuf[cnt++] = 0x00;
	CCM3310_WriteBuf[cnt++] = 0x00;
	CCM3310_WriteBuf[cnt++] = 0x00;
	CCM3310_WriteBuf[cnt++] = 0x00;

	//cmd
	CCM3310_WriteBuf[cnt++] = 0x80;     //CLA
	CCM3310_WriteBuf[cnt++] = Hash_Init_INS;
	CCM3310_WriteBuf[cnt++] = P1;      //select suanfa
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

  //------------------------------------------//

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#else
  usleep(200000);  //200ms  
#endif	 

  //read  
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16+4+8+32+4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//

	//read
	cnt = 0;
	for(i=0;i<16;i++)    //read bytes!
	{		
		cnt++;
	}
	for(i=0;i<4;i++)     //算法block len
	{		
		if(i==0)
		{
			*p_BLOCK_len = CCM3310_ReadBuf[cnt];
		}
		cnt++;
	}
	for(i=0;i<8;i++)
	{		
		pro_Buf[i] = CCM3310_ReadBuf[cnt];
		cnt++;
	}
	for(i=0;i<32;i++)
	{		
		med_Buf[i] = CCM3310_ReadBuf[cnt];
		cnt++;
	}
	for(i=0;i<4;i++)  //tail
	{		
		cnt++;
	}
	//------------------------------------------------------//	

	Write_analyse();	

	Read_analyse();


	//return
	if( (CCM3310_ReadBuf[STATE_OK_HB_P]==0x90)&&(CCM3310_ReadBuf[STATE_OK_LB_P]==0x00))   //90 00   正确执行
		return 1;  // 正确执行
	else
		return 0;
}

//P1 选着算法
//杂凑算法： 0x00 SM3 ）、 0x01 SHA0 ）、0x02 SHA1 ）、 0x03 SHA224 ）、 0x04 SHA256
//待更新的消息数据必须是 BLOCK_len 的整数倍。
//BLOCK_len 固定判断用了64
// pro_Buf  传出已处理长度
// med_Buf  传出中间值
// 实测下发的数据区部分不能超过4K  8+32+message_len  , message_len又要是64的倍数  所以 message_len 最大4032
uint8_t Hash_Update(uint8_t P1,uint8_t* message, uint32_t message_len, uint8_t* pro_Buf ,uint8_t* med_Buf)
{
  
  uint8_t ret = 0;

	uint32_t i,data_len;
	uint32_t cnt = 0;
	uint16_t LO_WORD_len,HI_WORD_len;
	uint8_t  LLO_BYTE_len,LHI_BYTE_len,HLO_BYTE_len,HHI_BYTE_len;

	data_len =  8+32+message_len; // 总的数据区长度!!!!!!!!
	if(message_len>HASH_UPDATE_EACH_MAXSIZE)
	{
		printf("Hash_Update 传入消息长度不能大于 4032! \r\n");
	}

	HI_WORD_len = HI_WORD(data_len);
	LO_WORD_len = LO_WORD(data_len);

	HHI_BYTE_len = HI_BYTE(HI_WORD_len);
	HLO_BYTE_len = LO_BYTE(HI_WORD_len);
	LHI_BYTE_len = HI_BYTE(LO_WORD_len);
	LLO_BYTE_len = LO_BYTE(LO_WORD_len);    //低字节

	if(message_len%64  !=  0) //非整数倍
	{
		printf("message_len 输入长度不是 BLOCK_len 64 的整数倍 \r\n\r\n");
	}

#if(USB_READY_IO==1)
	ccm3310s_Check_Ready();
#endif

  ins = Hash_Update_INS;

	//head
	CCM3310_WriteBuf[cnt++] = 0x53;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x10;
	CCM3310_WriteBuf[cnt++] = 0x33;

	//length
	CCM3310_WriteBuf[cnt++] = LLO_BYTE_len;
	CCM3310_WriteBuf[cnt++] = LHI_BYTE_len;
	CCM3310_WriteBuf[cnt++] = HLO_BYTE_len;
	CCM3310_WriteBuf[cnt++] = HHI_BYTE_len;

	//cmd
	CCM3310_WriteBuf[cnt++] = 0x80;    //CLA
	CCM3310_WriteBuf[cnt++] = Hash_Update_INS;    //INS
	CCM3310_WriteBuf[cnt++] = P1;       //select suanfa
	CCM3310_WriteBuf[cnt++] = 0x00;

	//reserve
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;

	//-------------------------------------//
	//data part
	for(i=0;i<8;i++)   //已处理长度8个字节
	{		 
		CCM3310_WriteBuf[cnt++] = Processed_Buf[i];   //全局变量!!!!
	}
	for(i=0;i<32;i++)   //中间值
	{		
		CCM3310_WriteBuf[cnt++] = Median_Buf[i];   //全局变量!!!!
	}
	for(i=0;i<message_len;i++)   //传入消息
	{		
		CCM3310_WriteBuf[cnt++] = message[i];
	}
	//-------------------------------------//

	 //tail
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x33;
	CCM3310_WriteBuf[cnt++] = 0x01;

  //send
  ret = transfer(spifd, CCM3310_WriteBuf, CCM3310_ReadBuf, cnt);
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }

  //-------------------------------------//
#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#else
  usleep(200000);  //200ms
#endif  
	 
  //read  
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 8+32 + 4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }

	//read
	cnt = 0;
	for(i=0;i<16;i++)    //read bytes!
	{
		cnt++;
	}
	for(i=0;i<8;i++)
	{
		pro_Buf[i] = CCM3310_ReadBuf[cnt];
		cnt++;
	}
	for(i=0;i<32;i++)
	{
		med_Buf[i] = CCM3310_ReadBuf[cnt];
		cnt++;
	}
	for(i=0;i<4;i++)  //tail
	{
		cnt++;
	}
	//-----------------------------------------------//

	//Write_analyse();
	//Read_analyse();

	//return
	if( (CCM3310_ReadBuf[STATE_OK_HB_P]==0x90)&&(CCM3310_ReadBuf[STATE_OK_LB_P]==0x00))   //90 00   正确执行
		return 1;  // 正确执行
	else
		return 0;

}

//uint32_t* message,
//P1 选着算法
//杂凑算法： 0x00 SM3 ）、 0x01 SHA0 ）、0x02 SHA1 ）、 0x03 SHA224 ）、 0x04 SHA256
//待更新的消息数据必须是 BLOCK_len 的整数倍。
//BLOCK_len 固定判断用了64
// pro_Buf  传出已处理长度
// med_Buf  传出中间值
// 实测下发的数据区部分不能超过4K  8+32+message_len  , message_len又要是64的倍数  所以 message_len 最大4032
//message  32位数组
//message_len   32位数组长度
uint8_t Hash_Update_image(uint8_t P1,uint32_t* message, uint32_t message_len, uint8_t* pro_Buf ,uint8_t* med_Buf)
{
	uint32_t i,data_len;
	uint32_t cnt = 0;
	uint16_t temp_LO_WORD,temp_HI_WORD;
	uint8_t  temp_LLO_BYTE,temp_LHI_BYTE,temp_HLO_BYTE,temp_HHI_BYTE;

	data_len =  8+32+message_len*4; // 总的数据区长度!!!!!!!!
	if((message_len*4)>HASH_UPDATE_EACH_MAXSIZE)
	{
		printf("Hash_Update 传入消息长度不能大于 4032! \r\n");
	}

	temp_HI_WORD = HI_WORD(data_len);
	temp_LO_WORD = LO_WORD(data_len);

	temp_HHI_BYTE = HI_BYTE(temp_HI_WORD);
	temp_HLO_BYTE = LO_BYTE(temp_HI_WORD);
	temp_LHI_BYTE = HI_BYTE(temp_LO_WORD);
	temp_LLO_BYTE = LO_BYTE(temp_LO_WORD);    //低字节

	if((message_len*4)%64  !=  0) //非整数倍
	{
		printf("message_len 输入长度不是 BLOCK_len 64 的整数倍 \r\n\r\n");
	}

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	CCM3310_WriteBuf[cnt++] = 0x53;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x10;
	CCM3310_WriteBuf[cnt++] = 0x33;

	//length
	SPI_ReadWriteOneByte(temp_LLO_BYTE);  //14
	SPI_ReadWriteOneByte(temp_LHI_BYTE);
	SPI_ReadWriteOneByte(temp_HLO_BYTE);
	SPI_ReadWriteOneByte(temp_HHI_BYTE);

	CCM3310_WriteBuf[cnt++] = temp_LLO_BYTE;
	CCM3310_WriteBuf[cnt++] = temp_LHI_BYTE;
	CCM3310_WriteBuf[cnt++] = temp_HLO_BYTE;
	CCM3310_WriteBuf[cnt++] = temp_HHI_BYTE;

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x4A);   //INS
	SPI_ReadWriteOneByte(P1);   //select suanfa
	SPI_ReadWriteOneByte(0x00);

	CCM3310_WriteBuf[cnt++] = 0x80;
	CCM3310_WriteBuf[cnt++] = 0x4A;
	CCM3310_WriteBuf[cnt++] = P1;
	CCM3310_WriteBuf[cnt++] = 0x00;

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;

	//-------------------------------------//
	//data part
	for(i=0;i<8;i++)   //已处理长度8个字节
	{
		SPI_ReadWriteOneByte(Processed_Buf[i]);       //全局变量!!!!
		CCM3310_WriteBuf[cnt++] = Processed_Buf[i];
	}
	for(i=0;i<32;i++)   //中间值
	{
		SPI_ReadWriteOneByte(Median_Buf[i]);          //全局变量!!!!
		CCM3310_WriteBuf[cnt++] = Median_Buf[i];
	}
			
	//传入消息
	for(i=0;i<message_len;i++)   
	{
		//拆成字节
		temp_HI_WORD = HI_WORD(message[i]);
		temp_LO_WORD = LO_WORD(message[i]);

		temp_HHI_BYTE = HI_BYTE(temp_HI_WORD);
		temp_HLO_BYTE = LO_BYTE(temp_HI_WORD);
		temp_LHI_BYTE = HI_BYTE(temp_LO_WORD);
		temp_LLO_BYTE = LO_BYTE(temp_LO_WORD);    //低字节
		
		//send   MCU 小端存储 
		SPI_ReadWriteOneByte(temp_LLO_BYTE);  
		SPI_ReadWriteOneByte(temp_LHI_BYTE);
		SPI_ReadWriteOneByte(temp_HLO_BYTE);
		SPI_ReadWriteOneByte(temp_HHI_BYTE);

		CCM3310_WriteBuf[cnt++] = temp_LLO_BYTE;
		CCM3310_WriteBuf[cnt++] = temp_LHI_BYTE;
		CCM3310_WriteBuf[cnt++] = temp_HLO_BYTE;
		CCM3310_WriteBuf[cnt++] = temp_HHI_BYTE;				
	}

	//-------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x33;
	CCM3310_WriteBuf[cnt++] = 0x01;

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();     //check RB pin

	/*1. 拉低片选*/
	 

	//read
	cnt = 0;
	for(i=0;i<16;i++)    //read bytes!
	{
		CCM3310_ReadBuf[cnt]=SPI_ReadWriteOneByte(0xFF);
		cnt++;
	}
	for(i=0;i<8;i++)
	{
		CCM3310_ReadBuf[cnt]=SPI_ReadWriteOneByte(0xFF);
		pro_Buf[i] = CCM3310_ReadBuf[cnt];
		cnt++;
	}
	for(i=0;i<32;i++)
	{
		CCM3310_ReadBuf[cnt]=SPI_ReadWriteOneByte(0xFF);
		med_Buf[i] = CCM3310_ReadBuf[cnt];
		cnt++;
	}
	for(i=0;i<4;i++)  //tail
	{
		CCM3310_ReadBuf[cnt]=SPI_ReadWriteOneByte(0xFF);
		cnt++;
	}

	/*5. 拉高片选*/
	 

	//-------------------------------------------------//

//	printf("Hash_Update 下发片数据:\r\n");
//
//	Write_analyse();
//
//	printf("Hash_Update 国芯芯片上行回复,小端  \r\n");
//
//	Read_analyse();
//
//	printf("Hash_Update 解密成功! \r\n\r\n");

	//return
	if( (CCM3310_ReadBuf[STATE_OK_HB_P]==0x90)&&(CCM3310_ReadBuf[STATE_OK_LB_P]==0x00))   //90 00   正确执行
		return 1;  // 正确执行
	else
		return 0;

}



//P1 选着算法
//杂凑算法： 0x00 SM3 ）、 0x01 SHA0 ）、0x02 SHA1 ）、 0x03 SHA224 ）、 0x04 SHA256
//message 最后一包消息数据, 长度不需要是 BLOCK_len 的整数倍。
// 实测下发的数据区部分不能超过4K  8+32+message_len  ,  message_len 最大4056
uint8_t Hash_Final(uint8_t P1,uint8_t* message, uint32_t message_len,uint8_t* OutPut_Hash)
{  
  uint8_t ret = 0;  
	uint32_t i,data_len;
	uint32_t cnt = 0;
	uint16_t LO_WORD_len,HI_WORD_len;
	uint8_t  LLO_BYTE_len,LHI_BYTE_len,HLO_BYTE_len,HHI_BYTE_len;

	data_len =  8+32+message_len; // 总的数据区长度!!!!!!!!
	if(message_len>HASH_FINAL_MAXSIZE)
	{
		printf("Hash_Final 传入消息长度不能大于 4056! \r\n");
	}

	HI_WORD_len = HI_WORD(data_len);
	LO_WORD_len = LO_WORD(data_len);

	HHI_BYTE_len = HI_BYTE(HI_WORD_len);
	HLO_BYTE_len = LO_BYTE(HI_WORD_len);
	LHI_BYTE_len = HI_BYTE(LO_WORD_len);
	LLO_BYTE_len = LO_BYTE(LO_WORD_len);    //低字节


#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = Hash_Final_INS;

	//head
	CCM3310_WriteBuf[cnt++] = 0x53;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x10;
	CCM3310_WriteBuf[cnt++] = 0x33;

	//length
	CCM3310_WriteBuf[cnt++] = LLO_BYTE_len;
	CCM3310_WriteBuf[cnt++] = LHI_BYTE_len;
	CCM3310_WriteBuf[cnt++] = HLO_BYTE_len;
	CCM3310_WriteBuf[cnt++] = HHI_BYTE_len;

	//cmd
	CCM3310_WriteBuf[cnt++] = 0x80;    //CLA
	CCM3310_WriteBuf[cnt++] = 0x4C;   //INS
	CCM3310_WriteBuf[cnt++] = P1;     //select suanfa
	CCM3310_WriteBuf[cnt++] = 0x00;

	//reserve
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;

	//-------------------------------------//
	//data part
	for(i=0;i<8;i++)   //已处理长度8个字节
	{		
		CCM3310_WriteBuf[cnt++] = Processed_Buf[i];    //全局变量！！！！
	}
	for(i=0;i<32;i++)   //中间值
	{		
		CCM3310_WriteBuf[cnt++] = Median_Buf[i];       //全局变量！！！！
	}
	for(i=0;i<message_len;i++)   //传入消息
	{		
		CCM3310_WriteBuf[cnt++] = message[i];
	}

	//-------------------------------------//
	 //tail
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x33;
	CCM3310_WriteBuf[cnt++] = 0x01;

  //send
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
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 32 + 4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
	 
	
	//read
	for(i=0;i<16;i++)    //read bytes!
	{		
	}

	for(i=0;i<32;i++)    //read hash
	{		
		OutPut_Hash[i] =  CCM3310_ReadBuf[16+i];   //save hash value
	}

	for(i=0;i<4;i++)    //read bytes!
	{		
	}	

	//------------------------------------------------------//
	//Write_analyse();

	Read_analyse();

	//return
	if( (CCM3310_ReadBuf[STATE_OK_HB_P]==0x90)&&(CCM3310_ReadBuf[STATE_OK_LB_P]==0x00))   //90 00   正确执行
		return 1;  // 正确执行
	else
		return 0;

}

//message  32位数组
//message_len   32位数组长度
uint8_t Hash_Final_image(uint8_t P1,uint32_t* message, uint32_t message_len)
{
	uint32_t i,data_len;
	uint32_t cnt = 0;
	uint16_t temp_LO_WORD,temp_HI_WORD;
	uint8_t  temp_LLO_BYTE,temp_LHI_BYTE,temp_HLO_BYTE,temp_HHI_BYTE;

	data_len =  8+32+message_len*4; // 总的数据区长度!!!!!!!!
	if((message_len*4)>HASH_FINAL_MAXSIZE)
	{
		printf("Hash_Final 传入消息长度不能大于 4056! \r\n");
	}

	temp_HI_WORD = HI_WORD(data_len);
	temp_LO_WORD = LO_WORD(data_len);

	temp_HHI_BYTE = HI_BYTE(temp_HI_WORD);
	temp_HLO_BYTE = LO_BYTE(temp_HI_WORD);
	temp_LHI_BYTE = HI_BYTE(temp_LO_WORD);
	temp_LLO_BYTE = LO_BYTE(temp_LO_WORD);    //低字节


	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	CCM3310_WriteBuf[cnt++] = 0x53;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x10;
	CCM3310_WriteBuf[cnt++] = 0x33;

	//length
	SPI_ReadWriteOneByte(temp_LLO_BYTE);  //14
	SPI_ReadWriteOneByte(temp_LHI_BYTE);
	SPI_ReadWriteOneByte(temp_HLO_BYTE);
	SPI_ReadWriteOneByte(temp_HHI_BYTE);

	CCM3310_WriteBuf[cnt++] = temp_LLO_BYTE;
	CCM3310_WriteBuf[cnt++] = temp_LHI_BYTE;
	CCM3310_WriteBuf[cnt++] = temp_HLO_BYTE;
	CCM3310_WriteBuf[cnt++] = temp_HHI_BYTE;

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x4C);   //INS
	SPI_ReadWriteOneByte(P1);   //select suanfa
	SPI_ReadWriteOneByte(0x00);

	CCM3310_WriteBuf[cnt++] = 0x80;
	CCM3310_WriteBuf[cnt++] = 0x4C;
	CCM3310_WriteBuf[cnt++] = P1;
	CCM3310_WriteBuf[cnt++] = 0x00;

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;

	//-------------------------------------//
	//data part
	for(i=0;i<8;i++)   //已处理长度8个字节
	{
		SPI_ReadWriteOneByte(Processed_Buf[i]);          //全局变量！！！！
		CCM3310_WriteBuf[cnt++] = Processed_Buf[i];
	}
	for(i=0;i<32;i++)   //中间值
	{
		SPI_ReadWriteOneByte(Median_Buf[i]);             //全局变量！！！！
		CCM3310_WriteBuf[cnt++] = Median_Buf[i];
	}
	//传入消息
	for(i=0;i<message_len;i++)   
	{
		//拆成字节
		temp_HI_WORD = HI_WORD(message[i]);
		temp_LO_WORD = LO_WORD(message[i]);

		temp_HHI_BYTE = HI_BYTE(temp_HI_WORD);
		temp_HLO_BYTE = LO_BYTE(temp_HI_WORD);
		temp_LHI_BYTE = HI_BYTE(temp_LO_WORD);
		temp_LLO_BYTE = LO_BYTE(temp_LO_WORD);    //低字节
		
		//send   MCU 小端存储 
		SPI_ReadWriteOneByte(temp_LLO_BYTE);  
		SPI_ReadWriteOneByte(temp_LHI_BYTE);
		SPI_ReadWriteOneByte(temp_HLO_BYTE);
		SPI_ReadWriteOneByte(temp_HHI_BYTE);

		CCM3310_WriteBuf[cnt++] = temp_LLO_BYTE;
		CCM3310_WriteBuf[cnt++] = temp_LHI_BYTE;
		CCM3310_WriteBuf[cnt++] = temp_HLO_BYTE;
		CCM3310_WriteBuf[cnt++] = temp_HHI_BYTE;				
	}

	//-------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x33;
	CCM3310_WriteBuf[cnt++] = 0x01;

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();    // check RB

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<(16+32+4);i++)    //read bytes!
	{
		CCM3310_ReadBuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 

	//------------------------------------------------------//


//	printf("Hash_Final 下发片数据:\r\n");
//
//	Write_analyse();

	printf("Hash_Final 国芯芯片上行回复,小端  \r\n");

	Read_analyse();

	printf("Hash_Final 解密成功! \r\n\r\n");


	//return
	if( (CCM3310_ReadBuf[STATE_OK_HB_P]==0x90)&&(CCM3310_ReadBuf[STATE_OK_LB_P]==0x00))   //90 00   正确执行
		return 1;  // 正确执行
	else
		return 0;

}


void Hash_Package(uint8_t* Input_Message, uint32_t Package_Len,uint32_t Each_hash_Len,uint8_t* OutPut_Hash)
{
	uint32_t i, Hash_Update_time;
	uint32_t Hash_Final_Message_Len;
	uint8_t ret;

	if(Package_Len%Each_hash_Len == 0)   //整除
	{
		Hash_Update_time = Package_Len/Each_hash_Len - 1;

		Hash_Final_Message_Len = Each_hash_Len;
	}
	else  //不整除
	{
		Hash_Update_time = Package_Len/Each_hash_Len;

		Hash_Final_Message_Len = Package_Len - Each_hash_Len*Hash_Update_time;
	}

	printf("Hash_Update_time %d  hash Final Message len %d \r\n",Hash_Update_time,Hash_Final_Message_Len);

	//-------------------------------------------------------//

	//1
	ret = Hash_Init(SHA256, &BLOCK_len,Processed_Buf,Median_Buf);

	if(ret)
		printf("Hash_Init ok \r\n\r\n");
	else
		printf("Hash_Init wrong \r\n\r\n");

	//2
	for(i=0;i<Hash_Update_time;i++)
	{
//		printf("----------------------------------------\r\n");

		ret = Hash_Update(SHA256,&Input_Message[Each_hash_Len*i],Each_hash_Len,Processed_Buf,Median_Buf);

		if(ret)
			printf("Hash_Update ok \r\n\r\n");
		else
			printf("Hash_Update wrong \r\n\r\n");
	}

	//3
	Hash_Final(SHA256,&Input_Message[Each_hash_Len*Hash_Update_time],Hash_Final_Message_Len,OutPut_Hash);
}

//uint32_t* Input_Message
// Package_Len      字节数
// Each_hash_Len    字节数   一般 就填  HASH_UPDATE_EACH_MAXSIZE  4032
void Hash_image(uint32_t* Input_Message, uint32_t Package_Len,uint32_t Each_hash_Len)
{
	uint32_t i, Hash_Update_time;
	uint32_t Hash_Final_Message_Len;   // 字节数
	uint8_t ret;
	
	if(Package_Len%4 !=  0) //非整数倍
	{
		printf("固件包不是 4 字节对齐，不是4 的整数倍!!!!!!!!!!!!!!!!!!!!!!!!!!! \r\n\r\n");
	}	
	

	if(Package_Len%Each_hash_Len == 0)   //整除
	{
		Hash_Update_time = Package_Len/Each_hash_Len - 1;

		Hash_Final_Message_Len = Each_hash_Len;
	}
	else  //不整除
	{
		Hash_Update_time = Package_Len/Each_hash_Len;

		Hash_Final_Message_Len = Package_Len - Each_hash_Len*Hash_Update_time;
	}

	printf("Hash_Update_time %d  hash Final Message 字节长度 %d \r\n",Hash_Update_time,Hash_Final_Message_Len);

	//-------------------------------------------------------//

	//1
	ret = Hash_Init(SHA256, &BLOCK_len,Processed_Buf,Median_Buf);

	if(ret)
		printf("Hash_Init ok \r\n\r\n");
	else
		printf("Hash_Init wrong \r\n\r\n");

	//2
	for(i=0;i<Hash_Update_time;i++)
	{
//		printf("----------------------------------------\r\n");

		ret = Hash_Update_image(SHA256,&Input_Message[Each_hash_Len*i/4],Each_hash_Len/4,Processed_Buf,Median_Buf);    //传入32位数组

		if(ret)
			printf("Hash_Update_image ok \r\n\r\n");
		else
			printf("Hash_Update_image wrong \r\n\r\n");
	}

	//3
	Hash_Final_image(SHA256,&Input_Message[Each_hash_Len*Hash_Update_time/4],Hash_Final_Message_Len/4);         //传入32位数组
}


//数据段最大 4Kbyte
//P1 选择算法
//message 传入消息
//message_len 消息长度
void Hash_Once(uint8_t P1,uint8_t* Input_Message, uint32_t message_len,uint8_t* OutPut_Hash)
{
  uint8_t cnt = 0;
  uint8_t ret = 0;
  uint32_t i = 0;

	uint16_t LO_WORD_len,HI_WORD_len;
	uint8_t  LLO_BYTE_len,LHI_BYTE_len,HLO_BYTE_len,HHI_BYTE_len;

	if(message_len>4096)
	{
		printf("下发的总数据区超过4096! \r\n");
	}

	HI_WORD_len = HI_WORD(message_len);
	LO_WORD_len = LO_WORD(message_len);

	HHI_BYTE_len = HI_BYTE(HI_WORD_len);
	HLO_BYTE_len = LO_BYTE(HI_WORD_len);
	LHI_BYTE_len = HI_BYTE(LO_WORD_len);
	LLO_BYTE_len = LO_BYTE(LO_WORD_len);    //低字节

   //---------------------------------//	 

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = Hash_Once_INS;
 

	//head
	CCM3310_WriteBuf[cnt++] = 0x53;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x10;
	CCM3310_WriteBuf[cnt++] = 0x33;

	//length
	CCM3310_WriteBuf[cnt++] = LLO_BYTE_len;
	CCM3310_WriteBuf[cnt++] = LHI_BYTE_len;
	CCM3310_WriteBuf[cnt++] = HLO_BYTE_len;
	CCM3310_WriteBuf[cnt++] = HHI_BYTE_len;

	//cmd
	CCM3310_WriteBuf[cnt++] = 0x80;      //CLA
	CCM3310_WriteBuf[cnt++] = Hash_Once_INS;   //INS
	CCM3310_WriteBuf[cnt++] = P1;
	CCM3310_WriteBuf[cnt++] = 0x00;

	//reserve
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;

	//data!
	for(i=0;i<message_len;i++)   //传入消息
	{
		CCM3310_WriteBuf[cnt++] = Input_Message[i];
	}

	 //tail
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x33;
	CCM3310_WriteBuf[cnt++] = 0x01;

  //send
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
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 32 + 4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//
	 
	
	//read
	for(i=0;i<16;i++)    //read bytes!
	{		
	}

	for(i=0;i<32;i++)    //read hash
	{		
		OutPut_Hash[i] =  CCM3310_ReadBuf[16+i];   //save hash value
	}

	for(i=0;i<4;i++)    //read bytes!
	{		
	}	

	//------------------------------------------------------//
	Read_analyse();
}

void Write_analyse(void)
{
	uint8_t i;
	uint16_t cnt =0;

  printf("\n ------------------------------------------- \n");

  if (ins == GetVersion_INS)
    printf("get version");
  else if (ins == GetSN_INS)
    printf("GetSN");
  else if (ins == GetRandom_INS)
    printf("GetRandom");
  else if( ins == Hash_Init_INS )
    printf("Hash_Init");
  else if (ins == Hash_Update_INS)
    printf("Hash_Update\r\n");
  else if (ins == Hash_Final_INS)
  	printf("Hash_Final\n");


  printf(" send data:\r\n");


	uint32_t length;
	uint16_t LO_WORD_len,HI_WORD_len;

	//-----------------------------------------//
	LO_WORD_len = MAKE_WORD(CCM3310_WriteBuf[4],CCM3310_WriteBuf[5]);
	HI_WORD_len = MAKE_WORD(CCM3310_WriteBuf[6],CCM3310_WriteBuf[7]);
	length = MAKE_LONG(LO_WORD_len,HI_WORD_len);
	//-----------------------------------------//

	printf("包头占固定4字节: \t");
	for(i=0;i<4;i++)
	{
		printf("%02X ",CCM3310_WriteBuf[cnt]);
		cnt++;
	}
	printf("\r\n");

	printf("数据长度占4字节 \t");
	for(i=0;i<4;i++)
	{
		printf("%02X ",CCM3310_WriteBuf[cnt]);
		cnt++;
	}

	printf("// %d 个字节 \r\n",length);

	printf("命令字段占4字节: \t\t");
	for(i=0;i<4;i++)
	{
		printf("%02X ",CCM3310_WriteBuf[cnt]);
		cnt++;
	}
	printf("\r\n");

	printf("保留字段占4字节: \t\t");
	for(i=0;i<4;i++)
	{
		printf("%02X ",CCM3310_WriteBuf[cnt]);
		cnt++;
	}
	printf("\r\n");

	//----------------------------------------------//
	if(CCM3310_WriteBuf[9]==0x48)  //hash init
	{
		printf("无数据区:	\r\n");
	}
	else if(CCM3310_WriteBuf[9]==0x4A)  //hash update
	{
		printf("数据部分:	\r\n");

		printf("已处理长度:	\r\n");
		for(i=0;i<8;i++)
		{
			printf("%02X ",CCM3310_WriteBuf[cnt]);
			cnt++;
		}
		printf("\r\n");

		printf("中间值32个字节:	\r\n");
		for(i=0;i<32;i++)
		{
			printf("%02X ",CCM3310_WriteBuf[cnt]);
			cnt++;
		}
		printf("\r\n");

		printf("Hash 输入消息值:	\r\n");
		for(i=0;i<(length-8-32);i++)
		{
			printf("%02X ",CCM3310_WriteBuf[cnt]);
			cnt++;
		}
		printf("\r\n");
	}
	else if(CCM3310_WriteBuf[9]==0x4C)  //hash Final
	{
		printf("数据部分:	\r\n");

		printf("已处理长度:	\r\n");
		for(i=0;i<8;i++)
		{
			printf("%02X ",CCM3310_WriteBuf[cnt]);
			cnt++;
		}
		printf("\r\n");

		printf("中间值32个字节:	\r\n");
		for(i=0;i<32;i++)
		{
			printf("%02X ",CCM3310_WriteBuf[cnt]);
			cnt++;
		}
		printf("\r\n");

		printf("Hash 输入最后一包消息值:	\r\n");
		for(i=0;i<(length-8-32);i++)
		{
			printf("%02X ",CCM3310_WriteBuf[cnt]);
			cnt++;
		}
		printf("\r\n");
	}
	else if(CCM3310_WriteBuf[9]==0x4E)  //hash onece
	{
		printf("传入消息数据:	\r\n");

		for(i=0;i<length;i++)
		{
			printf("%02X ",CCM3310_WriteBuf[cnt]);
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
	for(i=0;i<4;i++)
	{
		printf("%02X ",CCM3310_WriteBuf[cnt]);
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




//use public key in chip flash
//签名原始数据的 大小应不超过 128byte    IDA data 用的是国标的的IDA
void SM2_Calc_Z(uint8_t Key_ID, uint8_t* OutPut_Z)
{
  uint8_t cnt = 0;
  uint8_t ret = 0;
  uint32_t i = 0;

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = SM2_Calc_Z_INS;	 

	//head
	CCM3310_WriteBuf[cnt++] = (0x53);
	CCM3310_WriteBuf[cnt++] = (0x02);
	CCM3310_WriteBuf[cnt++] = (0x10);
	CCM3310_WriteBuf[cnt++] = (0x33);

	//length
	CCM3310_WriteBuf[cnt++] = ( (1+3+4+16) );
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);

	//cmd
	CCM3310_WriteBuf[cnt++] = (0x80);   //CLA
	CCM3310_WriteBuf[cnt++] = SM2_Calc_Z_INS;   //INS
	CCM3310_WriteBuf[cnt++] = (0x00);   //P1 use public key in chip flash
	CCM3310_WriteBuf[cnt++] = (0x00);

	//reserve
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);

	//---------------------------------------------//
	//data part
	CCM3310_WriteBuf[cnt++] = (Key_ID);    //key id
	CCM3310_WriteBuf[cnt++] = (0x00);      //reverse
	CCM3310_WriteBuf[cnt++] = (0x00); 	 //reverse
	CCM3310_WriteBuf[cnt++] = (0x00);      //reverse


	//IDA len
	CCM3310_WriteBuf[cnt++] = (0x10);
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);


	//IDA data   16 byte
	CCM3310_WriteBuf[cnt++] = (0x31);
	CCM3310_WriteBuf[cnt++] = (0x32);
	CCM3310_WriteBuf[cnt++] = (0x33);
	CCM3310_WriteBuf[cnt++] = (0x34);
	CCM3310_WriteBuf[cnt++] = (0x35);
	CCM3310_WriteBuf[cnt++] = (0x36);
	CCM3310_WriteBuf[cnt++] = (0x37);
	CCM3310_WriteBuf[cnt++] = (0x38);
	CCM3310_WriteBuf[cnt++] = (0x31);
	CCM3310_WriteBuf[cnt++] = (0x32);
	CCM3310_WriteBuf[cnt++] = (0x33);
	CCM3310_WriteBuf[cnt++] = (0x34);
	CCM3310_WriteBuf[cnt++] = (0x35);
	CCM3310_WriteBuf[cnt++] = (0x36);
	CCM3310_WriteBuf[cnt++] = (0x37);
	CCM3310_WriteBuf[cnt++] = (0x38);
	//---------------------------------------------//

	 //tail
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x02);
	CCM3310_WriteBuf[cnt++] = (0x33);
	CCM3310_WriteBuf[cnt++] = (0x01);

  //send
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
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 32 + 4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//	 
	//read
	for(i=0;i<16;i++)    //read bytes!
	{		
	}

	for(i=0;i<32;i++)    //read bytes!
	{		
		OutPut_Z[i] =  CCM3310_ReadBuf[16+i];   //save Z value
	}

	for(i=0;i<4;i++)    //read bytes!
	{		
	}
  //-------------------------------------------------//	 

	Read_analyse();
	
}



//use public key in chip flash
//签名原始数据的 大小应不超过 128byte
//return 1 ok  ; 0 not ok
uint8_t SM2_Calc_HASH(uint8_t* Inupt_Message, uint8_t InputLen, uint8_t Key_ID, uint8_t* OutPut_Hash)
{
	uint8_t i;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//length
	SPI_ReadWriteOneByte( (1+3+4+4+16+InputLen) );
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x6C);   //INS
	SPI_ReadWriteOneByte(0x00);   //P1 use public key in chip flash
	SPI_ReadWriteOneByte(0x00);

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	SPI_ReadWriteOneByte(Key_ID);    //key id
	SPI_ReadWriteOneByte(0x00);      //reverse
	SPI_ReadWriteOneByte(0x00); 	 //reverse
	SPI_ReadWriteOneByte(0x00);      //reverse


	//IDA len
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//need sign orignal data len
	SPI_ReadWriteOneByte(InputLen);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//IDA data
	SPI_ReadWriteOneByte(0x31);
	SPI_ReadWriteOneByte(0x32);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x34);
	SPI_ReadWriteOneByte(0x35);
	SPI_ReadWriteOneByte(0x36);
	SPI_ReadWriteOneByte(0x37);
	SPI_ReadWriteOneByte(0x38);
	SPI_ReadWriteOneByte(0x31);
	SPI_ReadWriteOneByte(0x32);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x34);
	SPI_ReadWriteOneByte(0x35);
	SPI_ReadWriteOneByte(0x36);
	SPI_ReadWriteOneByte(0x37);
	SPI_ReadWriteOneByte(0x38);
	//---------------------------------------------//

	//data need sign!
	for(i=0;i<InputLen;i++)
	{
		SPI_ReadWriteOneByte(Inupt_Message[i]);
	}

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();     // check RB pin

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<16;i++)    //read bytes!
	{
		CCM3310_ReadBuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	for(i=0;i<32;i++)    //read bytes!
	{
		CCM3310_ReadBuf[16+i]=SPI_ReadWriteOneByte(0xFF);

		OutPut_Hash[i] =  CCM3310_ReadBuf[16+i];   //save hash value
	}

	for(i=0;i<4;i++)    //read bytes!
	{
		CCM3310_ReadBuf[16+32+i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 
	
#ifdef LARRY_DEBUG_CCM3310	

	printf("SM2_Calc_HASH use key in chip flash, small store  \r\n");

	Read_analyse();

	printf("SM2_Calc_HASH use key in chip flash ,exe ok \r\n\r\n");
	
#endif
	
	//return
	if( (CCM3310_ReadBuf[STATE_OK_HB_P]==0x90)&&(CCM3310_ReadBuf[STATE_OK_LB_P]==0x00))   //90 00   正确执行
		return 1;  // 正确执行
	else
		return 0;	
}


//函数里面数据区数组暂时赋值500， 传入更大数据再开辟更大
// 芯片自带SM2计算hash函数传入数据大小限制128B;   SM2预处理，重写SM2 HASH 函数
void My_SM2_Calc_HASH(uint8_t* Inupt_Message, uint8_t InputLen, uint8_t Key_ID, uint8_t* OutPut_Hash)
{	
		uint8_t temp_buf[500];
		uint32_t i;
		uint32_t cnt=0;  //must init value! set 0!
	
	  //计算Z
		SM2_Calc_Z(Key_ID,Computed_Z);
		
		//数据拼接
		for(i=0;i<32;i++)
		{
			temp_buf[cnt++] = Computed_Z[i];
		}
		for(i=0;i<InputLen;i++)
		{
			temp_buf[cnt++] = Inupt_Message[i];
		}		
		
		//SM3  hash
		Hash_Once(SM3,temp_buf,cnt,OutPut_Hash);

}


//use public key in frame
//签名原始数据的 大小应不超过 128byte
void SM2_Calc_HASH2(uint8_t* Inupt_Message, uint8_t InputLen)
{
	uint8_t i;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//length
	SPI_ReadWriteOneByte( (64+4+4+16+InputLen) );
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x6C);   //INS
	SPI_ReadWriteOneByte(0x01);   // select use public ky in the frame
	SPI_ReadWriteOneByte(0x00);

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	//pub_key
	for(i=0;i<64;i++)
	{
		SPI_ReadWriteOneByte(Public_Key[i]);
	}

	//IDA len
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//need sign orignal data len
	SPI_ReadWriteOneByte(0x0E);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//IDA data
	SPI_ReadWriteOneByte(0x31);
	SPI_ReadWriteOneByte(0x32);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x34);
	SPI_ReadWriteOneByte(0x35);
	SPI_ReadWriteOneByte(0x36);
	SPI_ReadWriteOneByte(0x37);
	SPI_ReadWriteOneByte(0x38);
	SPI_ReadWriteOneByte(0x31);
	SPI_ReadWriteOneByte(0x32);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x34);
	SPI_ReadWriteOneByte(0x35);
	SPI_ReadWriteOneByte(0x36);
	SPI_ReadWriteOneByte(0x37);
	SPI_ReadWriteOneByte(0x38);
	//---------------------------------------------//

	//data need sign!
	for(i=0;i<InputLen;i++)
	{
		SPI_ReadWriteOneByte(Inupt_Message[i]);
	}

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<(16+32+4);i++)    //read bytes!
	{
		CCM3310_ReadBuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 

	printf("SM2_Calc_HASH 国芯芯片上行回复,小端  \r\n");

	Read_analyse();

	printf("SM2_Calc_HASH 执行成功! \r\n\r\n");
}





//ID      更新的ID号 ，仅更新时有用       	    FLASH中只你能存 4个密钥对   ID  01~04
//函数数据区 参数写死 01 密钥不可导出
void SM2_Import_Key(uint8_t* Input_Public_Key, uint8_t* Input_Private_Key, uint8_t ID)
{
  uint8_t cnt = 0;
  uint8_t ret = 0;
  uint32_t i = 0;

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = Import_Key_INS;	 

	//head
	CCM3310_WriteBuf[cnt++] = (0x53);
	CCM3310_WriteBuf[cnt++] = (0x02);
	CCM3310_WriteBuf[cnt++] = (0x10);
	CCM3310_WriteBuf[cnt++] = (0x33);

	//length
	CCM3310_WriteBuf[cnt++] = (0x64);  // 100   导入公私钥，数据区长度就为100
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);

	//cmd
	CCM3310_WriteBuf[cnt++] = (0x80);     //CLA     80/81 ：明文方式导入 SM2 密钥        C0/C1 ：线路保护方式导入 SM2 密钥
	CCM3310_WriteBuf[cnt++] = (Import_Key_INS);    //INS     固定5C
	CCM3310_WriteBuf[cnt++] = (0x01);    //P1      00: 新增密钥 01 ：更新密钥   默认用更新密钥对就行
	CCM3310_WriteBuf[cnt++] = (0x01);    //P2 00: 存储在 SRAM 01: 存储在 FLASH

	//reserve
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);

	//---------------------------------------------//
	//data part
	CCM3310_WriteBuf[cnt++] = (0x00);   //密钥结构体版本，当前为0
	CCM3310_WriteBuf[cnt++] = (ID);   // 更新的ID号 ，仅更新时有用
	CCM3310_WriteBuf[cnt++] = (0x01);   //密钥不可导出
	CCM3310_WriteBuf[cnt++] = (0x03);   //公私钥都导入

	//pub_key
	for(i=0;i<64;i++)
	{
		CCM3310_WriteBuf[cnt++] = (Input_Public_Key[i]);
	}

	//pri_key
	for(i=0;i<32;i++)
	{
		CCM3310_WriteBuf[cnt++] = (Input_Private_Key[i]);
	}
	//---------------------------------------------//

	 //tail
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x02);
	CCM3310_WriteBuf[cnt++] = (0x33);
	CCM3310_WriteBuf[cnt++] = (0x01);

  //send
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
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 1 + 4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//
	
	Read_analyse();
}

//ID      更新的ID号 ，仅更新时有用       	    FLASH中只你能存 4个密钥对   ID  01~04
//函数数据区 参数写死 01 密钥不可导出
void SM2_Import_pubKey(uint8_t* Input_Public_Key, uint8_t ID)
{
	uint8_t i;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//length
	SPI_ReadWriteOneByte(0x44);  // 4+64   导入公钥，数据区长度就为68
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//cmd
	SPI_ReadWriteOneByte(0x80);     //CLA     80/81 ：明文方式导入 SM2 密钥        C0/C1 ：线路保护方式导入 SM2 密钥
	SPI_ReadWriteOneByte(0x5C);    //INS     固定5C
	SPI_ReadWriteOneByte(0x01);    //P1      00: 新增密钥 01 ：更新密钥   默认用更新密钥对就行
	SPI_ReadWriteOneByte(0x01);    //P2 00: 存储在 SRAM 01: 存储在 FLASH

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	SPI_ReadWriteOneByte(0x00);   //密钥结构体版本，当前为0
	SPI_ReadWriteOneByte(ID);   // 更新的ID号 ，仅更新时有用
	SPI_ReadWriteOneByte(0x01);   //密钥不可导出
	SPI_ReadWriteOneByte(0x01);   //公钥导入

	//pub_key
	for(i=0;i<64;i++)
	{
		SPI_ReadWriteOneByte(Input_Public_Key[i]);
	}

	//---------------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<(16+1+4);i++)    //read bytes!
	{
		CCM3310_ReadBuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 

	printf("SM2_Import_pub Key 国芯芯片上行回复,小端  \r\n");

	Read_analyse();

	printf("SM2_Import_pub Key 执行成功! \r\n\r\n");


}

void ccm3310s_SM2_Sign(void)
{
	uint8_t readbuf[100];
	uint8_t i;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//length
	SPI_ReadWriteOneByte(0x40);  // 64
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x60);   //INS
	SPI_ReadWriteOneByte(0x01);   //use the key from comunication data
	SPI_ReadWriteOneByte(0x00);

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	//pri_key
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Private_Key[i]);
	}
	//data
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Message[i]);
	}

	//---------------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<84;i++)  //16+64+4
	{
		readbuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 


	//-------------------------------------------------//

	//printf
	printf("Frame data  \r\n");
	for(i=0;i<16;i++)
	{
		printf("%02x ",readbuf[i]);
	}
	printf("\r\n");
	for(i=0;i<64;i++)
	{
		printf("%02x ",readbuf[16+i]);
	}
	printf("\r\n");
	for(i=0;i<4;i++)
	{
		printf("%02x ",readbuf[16+64+i]);
	}
	printf("\r\n");

}

//使用flash中的的私钥签名
//Sign with fix random number
uint8_t SM2_Seed_Sign(uint8_t Key_ID,uint8_t* Hash_Val,uint8_t* Output_Signature)
{
	uint8_t i;
	uint8_t cnt = 0;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//length
	SPI_ReadWriteOneByte(0x44);  // 68
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);


	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x6E);   //INS
	SPI_ReadWriteOneByte(0x00);   //use the key in chip
	SPI_ReadWriteOneByte(0x00);

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	SPI_ReadWriteOneByte(Key_ID);    //key id
	SPI_ReadWriteOneByte(0x00);      //reverse
	SPI_ReadWriteOneByte(0x00); 	 //reverse
	SPI_ReadWriteOneByte(0x00);      //reverse

	//seed random number
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Known_Random[i]);
	}
	//data
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Hash_Val[i]);
	}

	//---------------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);


	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<16;i++)    //read bytes!
	{
		CCM3310_ReadBuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	for(i=0;i<64;i++)    //read bytes!
	{
		CCM3310_ReadBuf[16+i]=SPI_ReadWriteOneByte(0xFF);

		Output_Signature[i] =  CCM3310_ReadBuf[16+i];   //save Signature value
	}

	for(i=0;i<4;i++)    //read bytes!
	{
		CCM3310_ReadBuf[16+64+i]=SPI_ReadWriteOneByte(0xFF);
	}


	/*5. 拉高片选*/
	 

	//---------------------------------------------//
	
#ifdef LARRY_DEBUG_CCM3310	

	//printf
	printf("\r\n sm2 sign replay\r\n");

	Read_analyse();

	printf("SM2 sign success\r\n\r\n");
	
#endif
	
	//return
	if( (CCM3310_ReadBuf[STATE_OK_HB_P]==0x90)&&(CCM3310_ReadBuf[STATE_OK_LB_P]==0x00))   //90 00   正确执行
		return 1;  // 正确执行
	else
		return 0;			
}

//使用数据段中的私钥签名
void SM2_Seed_Sign2(void)   //Sign with random number
{
	uint8_t i;
	uint8_t cnt = 0;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	CCM3310_WriteBuf[cnt++] = 0x53;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x10;
	CCM3310_WriteBuf[cnt++] = 0x33;

	//length
	SPI_ReadWriteOneByte(0x60);  // 96
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	CCM3310_WriteBuf[cnt++] = 0x60;
	CCM3310_WriteBuf[cnt++] = 0x00;
	CCM3310_WriteBuf[cnt++] = 0x00;
	CCM3310_WriteBuf[cnt++] = 0x00;

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x6E);   //INS
	SPI_ReadWriteOneByte(0x01);   //use the key from comunication data
	SPI_ReadWriteOneByte(0x00);

	CCM3310_WriteBuf[cnt++] = 0x80;
	CCM3310_WriteBuf[cnt++] = 0x6E;
	CCM3310_WriteBuf[cnt++] = 0x01;
	CCM3310_WriteBuf[cnt++] = 0x00;

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x55;

	//---------------------------------------------//
	//data part
	//pri_key
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Private_Key[i]);

		CCM3310_WriteBuf[cnt++] = Private_Key[i];
	}
	//seed random number
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Known_Random[i]);

		CCM3310_WriteBuf[cnt++] = Known_Random[i];
	}
	//data
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Message[i]);

		CCM3310_WriteBuf[cnt++] = Message[i];
	}

	//---------------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	CCM3310_WriteBuf[cnt++] = 0x55;
	CCM3310_WriteBuf[cnt++] = 0x02;
	CCM3310_WriteBuf[cnt++] = 0x33;
	CCM3310_WriteBuf[cnt++] = 0x01;

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<84;i++)  //16+64+4
	{
		CCM3310_ReadBuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 

	//---------------------------------------------//
	printf("SM2带随机数的签名开始! \r\n");
	printf("下发给国芯加密芯片数据包:\r\n");

	Write_analyse();



	//printf
	printf("\r\n国芯加密芯片签名上行回复数据包 \r\n");

	Read_analyse();

	printf("SM2 签名成功! \r\n\r\n");

}

//use key in chip
//g改函数传入验签的数据是原始数据哈希后得到的固定32个字节的数据
// 1 验签成功
// 0 验签失败
uint8_t SM2_Verify(uint8_t Key_ID,uint8_t* Hash_Val ,uint8_t* Signature)
{	
  uint8_t cnt = 0;
  uint8_t ret = 0;
  uint32_t i = 0;

#if( USB_READY_IO == 1 )
  ccm3310s_Check_Ready();
#endif

  ins = SM2_Verify_INS;
  //---------------------------------//
	//head
	CCM3310_WriteBuf[cnt++] = (0x53);
	CCM3310_WriteBuf[cnt++] = (0x02);
	CCM3310_WriteBuf[cnt++] = (0x10);
	CCM3310_WriteBuf[cnt++] = (0x33);

	//length
	CCM3310_WriteBuf[cnt++] = (1+3+32+64);
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);
	CCM3310_WriteBuf[cnt++] = (0x00);

	//cmd
	CCM3310_WriteBuf[cnt++] = (0x80);   //CLA
	CCM3310_WriteBuf[cnt++] = (0x62);   //INS
	CCM3310_WriteBuf[cnt++] = (0x00);   //P1 use the key in chip
	CCM3310_WriteBuf[cnt++] = (0x00);

	//reserve
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x55);

	//---------------------------------------------//
	//data part
	CCM3310_WriteBuf[cnt++] = (Key_ID);    //key id
	CCM3310_WriteBuf[cnt++] = (0x00);      //reverse
	CCM3310_WriteBuf[cnt++] = (0x00); 	 //reverse
	CCM3310_WriteBuf[cnt++] = (0x00);      //reverse

	//data
	for(i=0;i<32;i++)
	{
		CCM3310_WriteBuf[cnt++] = (Hash_Val[i]);
	}
	//signed value
	for(i=0;i<64;i++)
	{
		CCM3310_WriteBuf[cnt++] = (Signature[i]);
	}
	//---------------------------------------------//

	 //tail
	CCM3310_WriteBuf[cnt++] = (0x55);
	CCM3310_WriteBuf[cnt++] = (0x02);
	CCM3310_WriteBuf[cnt++] = (0x33);
	CCM3310_WriteBuf[cnt++] = (0x01);

  //send
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
  ret = transfer(spifd, FILLBuf, CCM3310_ReadBuf, (16 + 4));
  if (-1 == ret)
  {
    printf("transfer error...\n");
  }
  //-------------------------------------------------//
	 	
	Read_analyse();
	
	if( (CCM3310_ReadBuf[9]==0x90)&&(CCM3310_ReadBuf[8]==0x00) )
	{
		printf("SM2 验签 成功!!!!!!!!!!!!!!!!!!! \r\n\r\n");
		return 1;
	}
	else
	{
		printf("SM2 验签 失败!!!!!!!!!!!!!!!!!!! \r\n\r\n");
		return 0;
	}

}


//use key in frame
//g改函数传入验签的数据是原始数据哈希后得到的固定32个字节的数据
void SM2_Verify2(void)
{	
	uint8_t i;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//length
	SPI_ReadWriteOneByte(0xA0);  // 160
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x62);   //INS
	SPI_ReadWriteOneByte(0x01);   //use the key from comunication data
	SPI_ReadWriteOneByte(0x00);

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	//pub_key
	for(i=0;i<64;i++)
	{
		SPI_ReadWriteOneByte(Public_Key[i]);
	}
	//data
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Known_Hash[i]);
	}
	//signed value
	for(i=0;i<64;i++)
	{
		SPI_ReadWriteOneByte(Known_Signature[i]);
	}
	//---------------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();	

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<20;i++)  //16+4
	{
		CCM3310_ReadBuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 

	//---------------------------------------------//
//	printf("SM2验签开始! \r\n");
//	printf("下发给国芯加密芯片数据包:\r\n");
//	printf("53 02 10 33 A0 00 00 00 80 62 01 00 55 55 55 55\r\n");
//	printf("F6 A6 87 AB 57 44 D5 CB BA 1C F9 3D 84 36 41 6F 75 C3 AE C3 D7 62 81 4D 56 53 14 AF F5 7A 89 F9  \r\n");
//	printf("F1 B8 EE 05 41 74 05 65 49 1E 44 04 3D E5 3C F5 BB ED D6 13 33 07 12 60 DF C5 78 3F 47 A7 B9 81\r\n");
//	printf("11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11\r\n");
//	printf("f4 21 d5 20 ed 0e e3 68 26 fe a8 26 2c 6d ce 8a 08 ae 6f ab 70 e9 d7 ee c5 9f a8 a1 d6 2d 01 df \r\n");
//	printf("e7 3f 97 f7 d2 69 21 1a 1c 30 f4 8b 0d cd dc 39 a3 88 83 b4 f2 55 ef 2f a1 2f b1 9a 7c 6d c8 aa \r\n");
//	printf("55 02 33 01\r\n");
//
//	printf("\r\n分析下发数据包:\r\n");
//	printf("包头占4字节:    	53 02 10 33   \r\n");
//	printf("数据长度占4字节 :	A0 00 00 00   数据段部分字节长度160个字节\r\n");
//	printf("使用数据段中密钥:	80 62 01 00  \r\n");
//	printf("保留字段占4字节:	55 55 55 55  \r\n");
//	printf("公钥64字节:		F6 A6 87 AB 57 44 D5 CB BA 1C F9 3D 84 36 41 6F 75 C3 AE C3 D7 62 81 4D 56 53 14 AF F5 7A 89 F9  \r\n");
//	printf("			F1 B8 EE 05 41 74 05 65 49 1E 44 04 3D E5 3C F5 BB ED D6 13 33 07 12 60 DF C5 78 3F 47 A7 B9 81  \r\n");
//	printf("签名原始数据: 		11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 \r\n");
//	printf("签名后64字节数据: 	f4 21 d5 20 ed 0e e3 68 26 fe a8 26 2c 6d ce 8a 08 ae 6f ab 70 e9 d7 ee c5 9f a8 a1 d6 2d 01 df  \r\n");
//	printf("        		e7 3f 97 f7 d2 69 21 1a 1c 30 f4 8b 0d cd dc 39 a3 88 83 b4 f2 55 ef 2f a1 2f b1 9a 7c 6d c8 aa  \r\n");
//	printf("下发包尾:		55 02 33 01  \r\n");


	printf("SM2 验签 国芯芯片上行回复,小端  \r\n");

	Read_analyse();

	printf("SM2 验签 执行成功! \r\n\r\n");

}

void SM2_Encrypt(void)
{
	uint8_t readbuf[100];
	uint8_t i;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//length
	SPI_ReadWriteOneByte(0x46);  // 70
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x64);   //INS
	SPI_ReadWriteOneByte(0x01);   //use the key from comunication data
	SPI_ReadWriteOneByte(0x00);

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	//pub_key
	for(i=0;i<64;i++)
	{
		SPI_ReadWriteOneByte(Public_Key[i]);
	}
	//data len
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//data
	SPI_ReadWriteOneByte(0x01);
	SPI_ReadWriteOneByte(0x02);
	//---------------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<118;i++)  //16+98+4
	{
		readbuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 

	//---------------------------------------------//
	printf("SM2加密开始! \r\n");
	printf("下发给国芯加密芯片数据包:\r\n");
	printf("53 02 10 33 46 00 00 00 80 64 01 00 55 55 55 55\r\n");
	printf("F6 A6 87 AB 57 44 D5 CB BA 1C F9 3D 84 36 41 6F 75 C3 AE C3 D7 62 81 4D 56 53 14 AF F5 7A 89 F9  \r\n");
	printf("F1 B8 EE 05 41 74 05 65 49 1E 44 04 3D E5 3C F5 BB ED D6 13 33 07 12 60 DF C5 78 3F 47 A7 B9 81 \r\n");
	printf("02 00 00 00\r\n");
	printf("01 02\r\n");
	printf("55 02 33 01\r\n");

	printf("\r\n分析下发数据包:\r\n");
	printf("包头占4字节:    	53 02 10 33   \r\n");
	printf("数据长度占4字节 :	46 00 00 00   数据段部分字节长度70个字节\r\n");
	printf("使用数据段中密钥:	80 64 01 00 \r\n");
	printf("保留字段占4字节:	55 55 55 55  \r\n");
	printf("公钥64字节:		F6 A6 87 AB 57 44 D5 CB BA 1C F9 3D 84 36 41 6F 75 C3 AE C3 D7 62 81 4D 56 53 14 AF F5 7A 89 F9  \r\n");
	printf("			F1 B8 EE 05 41 74 05 65 49 1E 44 04 3D E5 3C F5 BB ED D6 13 33 07 12 60 DF C5 78 3F 47 A7 B9 81  \r\n");
	printf("加密数据长度占4字节:	02 00 00 00 \r\n");
	printf("加密原始数据: 		01 02 \r\n");
	printf("下发包尾:		55 02 33 01  \r\n");

	//printf
	printf("\r\n国芯加密芯片加密上行回复数据包 \r\n");
	for(i=0;i<16;i++)
	{
		printf("%02x ",readbuf[i]);
	}
	printf("\r\n");

//	printf("Encrypt data  \r\n");
	for(i=0;i<98;i++)
	{
		printf("%02x ",readbuf[16+i]);
		Computed_EncryptData[i] = readbuf[16+i];  //save in buf
	}
	printf("\r\n");

	for(i=0;i<4;i++)
	{
		printf("%02x ",readbuf[16+98+i]);
	}
	printf("\r\n");

	printf("\r\n分析上行回复数据包:\r\n");
	printf("包头占4字节:    	52 02 10 33   \r\n");
	printf("数据长度占4字节 :	62 00 00 00  数据段部分字节长度98个字节\r\n");
	printf("状态字占2字节:	    	00 90  	表示加密成功\r\n");
	printf("保留字段6字节:	    	5A 5A 5A 5A 5A 5A  \r\n");
	printf("加密结果数据98个字节:	 \r\n");

	for(i=0;i<98;i++)
	{
		printf("%02x ",readbuf[16+i]);
		Computed_EncryptData[i] = readbuf[16+i];  //save in buf
	}
	printf("\r\n");

	printf("上行包尾:		56 02 33 01   \r\n");

	printf("SM2 加密成功! \r\n\r\n");


	printf("-----------------------------------------------------------------\r\n");

}

void SM2_Decrypt(void)
{
	uint8_t readbuf[100];
	uint8_t i;

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//head
	SPI_ReadWriteOneByte(0x53);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x10);
	SPI_ReadWriteOneByte(0x33);

	//data part length
	SPI_ReadWriteOneByte(0x86);  //  32+4+98个数据 134
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//cmd
	SPI_ReadWriteOneByte(0x80);   //CLA
	SPI_ReadWriteOneByte(0x66);   //INS
	SPI_ReadWriteOneByte(0x01);   //use the key from comunication data
	SPI_ReadWriteOneByte(0x00);

	//reserve
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x55);

	//---------------------------------------------//
	//data part
	//Private_Key
	for(i=0;i<32;i++)
	{
		SPI_ReadWriteOneByte(Private_Key[i]);
	}
	//data len
	SPI_ReadWriteOneByte(0x62);   //98 only test
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);
	SPI_ReadWriteOneByte(0x00);

	//Computed_EncryptData
	for(i=0;i<98;i++)
	{
		SPI_ReadWriteOneByte(Computed_EncryptData[i]);
	}
	//---------------------------------------------//

	 //tail
	SPI_ReadWriteOneByte(0x55);
	SPI_ReadWriteOneByte(0x02);
	SPI_ReadWriteOneByte(0x33);
	SPI_ReadWriteOneByte(0x01);

	/*5. 拉高片选*/
	 

	ccm3310s_Check_Ready();

	/*1. 拉低片选*/
	 

	//read
	for(i=0;i<22;i++)  //16+2+4
	{
		readbuf[i]=SPI_ReadWriteOneByte(0xFF);
	}

	/*5. 拉高片选*/
	 

	//---------------------------------------------//
	printf("SM2解密开始! \r\n");
	printf("下发给国芯加密芯片数据包:\r\n");
	printf("53 02 10 33 86 00 00 00 80 66 01 00 55 55 55 55\r\n");
	printf("6C B2 8D 99 38 5C 17 5C 94 F9 4E 93 48 17 66 3F C1 76 D9 25 DD 72 B7 27 26 0D BA AE 1F B2 F9 6F  \r\n");
	printf("62 00 00 00 \r\n");

	//Computed_EncryptData
	for(i=0;i<98;i++)
	{
		printf("%02x ",Computed_EncryptData[i]);
	}

	printf("55 02 33 01\r\n");

	printf("\r\n分析下发数据包:\r\n");
	printf("包头占4字节:    	53 02 10 33   \r\n");
	printf("数据长度占4字节 :	86 00 00 00  数据段部分字节长度134个字节\r\n");
	printf("使用数据段中密钥:	80 66 01 00 \r\n");
	printf("保留字段占4字节:	55 55 55 55  \r\n");
	printf("私钥32字节:		6C B2 8D 99 38 5C 17 5C 94 F9 4E 93 48 17 66 3F C1 76 D9 25 DD 72 B7 27 26 0D BA AE 1F B2 F9 6F  \r\n");
	printf("解密数据长度占4字节	62 00 00 00  \r\n");
	printf("要解密数据 \r\n");
	for(i=0;i<98;i++)
	{
		printf("%02x ",Computed_EncryptData[i]);
	}
	printf("\r\n下发包尾:		55 02 33 01  \r\n");

	//printf
	printf("\r\nSM2国芯芯片解密上行回复 \r\n");
	for(i=0;i<16;i++)
	{
		printf("%02x ",readbuf[i]);
	}
	printf("\r\n");

	printf("Orignal data  \r\n");
	for(i=0;i<2;i++)
	{
		printf("%02x ",readbuf[16+i]);
	}
	printf("\r\n");

	for(i=0;i<4;i++)
	{
		printf("%02x ",readbuf[16+2+i]);
	}
	printf("\r\n");
	printf("\r\n");


	printf("\r\n分析上行回复数据包:\r\n");
	printf("包头占4字节:    	52 02 10 33   \r\n");
	printf("数据长度占4字节 :	02 00 00 00  数据段部分字节长度2个字节\r\n");
	printf("状态字占2字节:	    	00 90  	表示解密密成功\r\n");
	printf("保留字段6字节:	    	5A 5A 5A 5A 5A 5A  \r\n");
	printf("解密后原始数据:	 	01 02\r\n");
	printf("上行包尾:		56 02 33 01   \r\n");

	printf("SM2 解密成功! \r\n\r\n");

}







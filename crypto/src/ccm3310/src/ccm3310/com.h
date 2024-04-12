/**
* @file        com.h
* @brief       
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/

#ifndef __COM_H_
#define __COM_H_ 	

#include "../drivers/drvlib.h"


#define USB_READY_IO    1   //    1  use    0 not use


//function id
#define GetVersion_INS     0x30
#define GetSN_INS          0x32

#define GetRandom_INS      0x40
#define Hash_Init_INS      0x48
#define Hash_Update_INS    0x4A
#define Hash_Final_INS     0x4C

#define Hash_Once_INS     0x4E

#define Import_Key_INS     0x5C
#define SM2_Calc_Z_INS     0x6A

#define SM2_Verify_INS     0x62


//杂凑算法： 0x00 SM3 ）、 0x01 SHA0 ）、0x02 SHA1 ）、 0x03 SHA224 ）、 0x04 SHA256

#define SM3 		0
#define SHA0  		1
#define SHA1  		2
#define SHA224  	3
#define SHA256  	4

//正确执行 9000
#define STATE_OK_HB  	90
#define STATE_OK_LB  	00

//在上行回复数组中位置
#define STATE_OK_HB_P  	9     //90位置
#define STATE_OK_LB_P  	8     //00 位置

#define MESSAGE_SIZE  	4096

#define HASH_UPDATE_EACH_MAXSIZE  4032  //实测下发的数据区部分不能超过4K  8+32+message_len  , message_len又要是64的倍数
#define HASH_FINAL_MAXSIZE        4056  //实测下发的数据区部分不能超过4K  8+32+message_len  ,  message_len 最大4056
//-------------------------------------------------------//

#define TEST_DATA_SIZE  2048
extern uint8_t test_data[TEST_DATA_SIZE];

extern uint8_t ins;     //function ID  (only part)

extern uint8_t CCM3310_WriteBuf[4096];    // send the data to ccm3310
extern uint8_t FILLBuf[4096];    // send the data to ccm3310
extern uint8_t CCM3310_ReadBuf[1024];    // receive the data from ccm3310

//移植到arm-linux 重新调试过OK的功能函数!
void Write_analyse(void);   // 解析Hash_Update    Hash_Final  不正常
void Read_analyse(void);

void printf_HexBuf(uint8_t* ram, uint32_t n);

#endif






























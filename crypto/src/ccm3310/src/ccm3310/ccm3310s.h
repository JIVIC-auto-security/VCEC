/**
* @file        ccm3310s.h
* @brief       chip:   国芯加密芯片CCM3310S-T 应用层协议
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/


#ifndef CCM3310S_H_
#define CCM3310S_H_

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





extern uint8_t ins;     //function ID  (only part)

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


extern const uint8_t Known_SM2_Private_Key[32];
extern const uint8_t Known_SM2_Public_Key[64];
extern const uint8_t Know_Message[14];
extern const uint8_t Known_Hash[32];
extern const uint8_t Known_Signature[64];

extern const uint8_t Known_Service_SM2_Public_Key[64];


extern uint8_t Message[MESSAGE_SIZE];
extern uint8_t Computed_Z[32];
extern uint8_t Computed_Hash[32];
extern uint8_t Computed_Signature[64];

extern const uint8_t Test_Signature[64];

extern uint8_t BLOCK_len;
extern uint8_t Processed_Buf[8];
extern uint8_t Median_Buf[32];

//--------------------------------------------------------------//
//移植到arm-linux 重新调试过OK的功能函数!
void Write_analyse(void);   // 解析Hash_Update    Hash_Final  不正常
void Read_analyse(void);

void ccm3310s_GetVersion(void);
void ccm3310s_GetSN(uint8_t* outputSN);
void ccm3310s_GetRandom(void);

uint8_t Hash_Init(uint8_t P1, uint8_t* p_BLOCK_len, uint8_t* pro_Buf, uint8_t* med_Buf);
uint8_t Hash_Update(uint8_t P1, uint8_t* message, uint32_t message_len, uint8_t* pro_Buf, uint8_t* med_Buf);
uint8_t Hash_Final(uint8_t P1, uint8_t* message, uint32_t message_len, uint8_t* OutPut_Hash);
void Hash_Package(uint8_t* Input_Message, uint32_t Package_Len, uint32_t Each_hash_Len, uint8_t* OutPut_Hash);



void SM2_Import_Key(uint8_t* Input_Public_Key, uint8_t* Input_Private_Key, uint8_t ID);

void SM2_Calc_Z(uint8_t Key_ID, uint8_t* OutPut_Z);
void Hash_Once(uint8_t P1, uint8_t* message, uint32_t message_len, uint8_t* OutPut_Hash);

void My_SM2_Calc_HASH(uint8_t* Inupt_Message, uint8_t InputLen, uint8_t Key_ID, uint8_t* OutPut_Hash);


uint8_t SM2_Verify(uint8_t Key_ID, uint8_t* Hash_Val, uint8_t* Signature);
//--------------------------------------------------------------//

void SM2_Import_pubKey(uint8_t* Input_Public_Key, uint8_t ID);

uint8_t Hash_Update_image(uint8_t P1,uint32_t* message, uint32_t message_len, uint8_t* pro_Buf ,uint8_t* med_Buf);
uint8_t Hash_Final_image(uint8_t P1,uint32_t* message, uint32_t message_len);
void Hash_image(uint32_t* Input_Message, uint32_t Package_Len,uint32_t Each_hash_Len);


uint8_t SM2_Calc_HASH(uint8_t* Inupt_Message, uint8_t InputLen, uint8_t Key_ID, uint8_t* OutPut_Hash);


uint8_t SM2_Seed_Sign(uint8_t Key_ID,uint8_t* Hash_Val,uint8_t* Output_Signature);

void SM2_Verify2(void);

void SM2_Encrypt(void);
void SM2_Decrypt(void);

//-----------------------------------//

void ccm3310s_SM2_Sign(void);

#endif /* CCM3310S_H_ */

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
#include "com.h"




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

void Hash_Once(uint8_t P1, uint8_t* message, uint32_t message_len, uint8_t* OutPut_Hash);

//--------------------------------------------------------------//
uint8_t Hash_Init(uint8_t P1, uint8_t* p_BLOCK_len, uint8_t* pro_Buf, uint8_t* med_Buf);
uint8_t Hash_Update(uint8_t P1, uint8_t* message, uint32_t message_len, uint8_t* pro_Buf, uint8_t* med_Buf);
uint8_t Hash_Final(uint8_t P1, uint8_t* message, uint32_t message_len, uint8_t* OutPut_Hash);





void SM2_Import_Key(uint8_t* Input_Public_Key, uint8_t* Input_Private_Key, uint8_t ID);

void SM2_Calc_Z(uint8_t Key_ID, uint8_t* OutPut_Z);


void My_SM2_Calc_HASH(uint8_t* Inupt_Message, uint8_t InputLen, uint8_t Key_ID, uint8_t* OutPut_Hash);
uint8_t SM2_Verify(uint8_t Key_ID, uint8_t* Hash_Val, uint8_t* Signature);
//--------------------------------------------------------------//

void SM2_Import_pubKey(uint8_t* Input_Public_Key, uint8_t ID);




uint8_t SM2_Calc_HASH(uint8_t* Inupt_Message, uint8_t InputLen, uint8_t Key_ID, uint8_t* OutPut_Hash);


uint8_t SM2_Seed_Sign(uint8_t Key_ID,uint8_t* Hash_Val,uint8_t* Output_Signature);


void SM2_Verify2(void);

void SM2_Encrypt(void);
void SM2_Decrypt(void);

//-----------------------------------//

void ccm3310s_SM2_Sign(void);

//--------------------------------------//

void Hash_Package(uint8_t* Input_Message, uint32_t Package_Len, uint32_t Each_hash_Len, uint8_t* OutPut_Hash);


uint8_t Hash_Update_image(uint8_t P1, uint32_t* message, uint32_t message_len, uint8_t* pro_Buf, uint8_t* med_Buf);
uint8_t Hash_Final_image(uint8_t P1, uint32_t* message, uint32_t message_len);
void Hash_image(uint32_t* Input_Message, uint32_t Package_Len, uint32_t Each_hash_Len);

#endif /* CCM3310S_H_ */

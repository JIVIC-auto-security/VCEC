/**
* @file        ccm3310s_test.c
* @brief       encrypt_module 
* @details   
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/

#include "../ccm3310/basic.h"
#include "../ccm3310/ccm3310s.h"


#define  USAGE()    fprintf(stderr, "usage:\n"  \
                "    %s <GetVersion          "   \
                    "  |2|...>\n"  , argv[0])

int main(int argc, char* argv[])
{
  printf("ccm3310s_test test V0.0.2 \r\n");

  /* 校验传参 */
  if (2 > argc) {
    USAGE();
    exit(-1);
  }
  led_init();
  ccm3310s_Init();

  if (!strcmp(argv[1], "GetVersion")) {
    ccm3310s_GetVersion();    
  }
  else if (!strcmp(argv[1], "GetSN")) {
    ccm3310s_GetSN(chip_SN);

    printf_HexBuf(chip_SN,sizeof(chip_SN));
  }
  else if (!strcmp(argv[1], "GetRandom")) {
    ccm3310s_GetRandom();
  }
  else if (!strcmp(argv[1], "Hash_Once")) {
    Hash_Once(4, test_data,sizeof(test_data), Computed_Hash);

    printf_HexBuf(Computed_Hash, sizeof(Computed_Hash));
  }
 // else if (!strcmp(argv[1], "Hash_Package")) {
 //  for(int i=0;i<MESSAGE_SIZE;i++)
	//{
	//	Message[i] = (i%256);
	//}

 //  Hash_Package(Message, MESSAGE_SIZE, 1024, Computed_Hash);

 //  printf_HexBuf(Computed_Hash, sizeof(Computed_Hash));
 // }
  else if (!strcmp(argv[1], "4")) {
    SM2_Import_Key(Known_SM2_Public_Key,Known_SM2_Private_Key,1);  
  }
  else if (!strcmp(argv[1], "5")) {
    //My_SM2_Calc_HASH(Rec_TargetData_Buf, Data_Sign_Offset, 1, Computed_Hash); //SM2 data hash预处理
  }
  else
  {
    USAGE();
    exit(-1);
  }


  while (1)
  {    
    LED_RUN(LED_ON);
    LED_NET(LED_ON);
    sleep(1);

    LED_RUN(LED_OFF);
    LED_NET(LED_OFF);
    sleep(1);
  }

   
}

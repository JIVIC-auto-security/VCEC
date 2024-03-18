/**
* @file        ccm3310s_test.c
* @brief       encrypt_module 
* @details   
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/


#include "../ccm3310/ccm3310s.h"


#define  USAGE()    fprintf(stderr, "usage:\n"  \
                "    %s <1|2|...>\n"  , argv[0])

int main(int argc, char* argv[])
{
  printf("ccm3310s_test test V0.1 \r\n");

  /* 校验传参 */
  if (2 > argc) {
    USAGE();
    exit(-1);
  }
  led_init();
  ccm3310s_Init();

  if (!strcmp(argv[1], "1")) {
    ccm3310s_GetVersion();    
  }
  else if (!strcmp(argv[1], "2")) {
    ccm3310s_GetRandom();
  }
  else if (!strcmp(argv[1], "3")) {
   for(int i=0;i<MESSAGE_SIZE;i++)
	{
		Message[i] = (i%256);
	}

   Hash_Package(Message, MESSAGE_SIZE, 1024, Computed_Hash);
  }
  else if (!strcmp(argv[1], "4")) {
    SM2_Import_Key(Known_SM2_Public_Key,Known_SM2_Private_Key,1);  
  }
  else if (!strcmp(argv[1], "5")) {
    //My_SM2_Calc_HASH(Rec_TargetData_Buf, Data_Sign_Offset, 1, Computed_Hash); //SM2 data hash预处理
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

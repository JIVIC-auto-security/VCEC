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
  printf("ccm3310s_test test V0.0.4 \r\n");

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

    printf_HexBuf(chip_SN, sizeof(chip_SN));
  }
  else if (!strcmp(argv[1], "GetRandom")) {
    ccm3310s_GetRandom();
  }
  else if (!strcmp(argv[1], "Hash_Once")) {
    Hash_Once(4, test_data, sizeof(test_data), Computed_Hash);

    printf_HexBuf(Computed_Hash, sizeof(Computed_Hash));
  }
  else if (!strcmp(argv[1], "Hash_Package")) {
    for (int i = 0; i < MESSAGE_SIZE; i++)
    {
      Message[i] = (i % 256);
    }

    Hash_Package(Message, MESSAGE_SIZE, 1024, Computed_Hash);

    printf_HexBuf(Computed_Hash, sizeof(Computed_Hash));
  }
  else if (!strcmp(argv[1], "SM2_Import_Key")) {
    SM2_Import_Key(Known_SM2_Public_Key, Known_SM2_Private_Key, 1);
  }
  else if (!strcmp(argv[1], "SM2_Encrypt")) {
    SM2_Encrypt();
  }
  else if (!strcmp(argv[1], "SM2_Decrypt")) {
    SM2_Decrypt();
  }
  else if (!strcmp(argv[1], "SM2_Seed_Sign")) {
    SM2_Seed_Sign(1, (uint8_t*)Known_Hash, Computed_Signature);

    printf_HexBuf(Computed_Signature, sizeof(Computed_Signature));
  }
  else if (!strcmp(argv[1], "SM2_Calc_Z")) {
    My_SM2_Calc_HASH(test_data, 100, 1, Computed_Hash); //SM2 data hash预处理
  }
  else if (!strcmp(argv[1], "SM2_Verify")) {
      
    int check_ret = SM2_Verify(1, (uint8_t*)Known_Hash, (uint8_t*)Known_Signature);   //test

    if (check_ret)  
    {
      DEBUG("SM2_Verify correct \r\n");      
    }
    else           
    {
      DEBUG("SM2_Verify wrong \r\n");      
    }

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

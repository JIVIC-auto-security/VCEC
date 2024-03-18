/**
* @file        drvlib_led.c
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "drvlib_led.h"


//above led
#define  LED1_TRIGGER    "/sys/class/leds/led1/trigger"
#define  LED1_BRIGHTNESS "/sys/class/leds/led1/brightness"

//below led
#define  LED2_TRIGGER    "/sys/class/leds/led2/trigger"
#define  LED2_BRIGHTNESS "/sys/class/leds/led2/brightness"

uint8_t RunLED_state = LED_ON;
uint8_t GNSSLED_state = LED_ON;


int ledRun_fd1 = 0;
int ledRun_fd2 = 0;

int ledNet_fd1 = 0;
int ledNet_fd2 = 0;


void ledRun_Fd_Create(void)
{
  /* 打开文件 */
  ledRun_fd1 = open(LED1_TRIGGER, O_RDWR);
  if (0 > ledRun_fd1) {
    perror("open error");
  }

  ledRun_fd2 = open(LED1_BRIGHTNESS, O_RDWR);
  if (0 > ledRun_fd2) {
    perror("open error");
  }

}


void ledNet_Fd_Create(void)
{
  /* 打开文件 */
  ledNet_fd1 = open(LED2_TRIGGER, O_RDWR);
  if (0 > ledNet_fd1) {
    perror("open error");    
  }

  ledNet_fd2 = open(LED2_BRIGHTNESS, O_RDWR);
  if (0 > ledNet_fd2) {
    perror("open error");    
  }

}


void led_init(void)
{
  ledRun_Fd_Create();

  ledNet_Fd_Create();
}



void LED_RUN(uint8_t led_state)
{
  if (led_state == LED_ON)
  {
    write(ledRun_fd1, "none", 4); 	//先将触发模式设置为none
    write(ledRun_fd2, "1", 1); 		//点亮LED
  }
  else
  {
    write(ledRun_fd1, "none", 4); 	//先将触发模式设置为none
    write(ledRun_fd2, "0", 1); 		//LED灭
  }

}


void LED_NET(uint8_t led_state)
{

  if (led_state == LED_ON)
  {
    write(ledNet_fd1, "none", 4); 	//先将触发模式设置为none
    write(ledNet_fd2, "1", 1); 		//点亮LED
  }
  else
  {
    write(ledNet_fd1, "none", 4); 	//先将触发模式设置为none
    write(ledNet_fd2, "0", 1); 		//LED灭
  }

}



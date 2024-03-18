/**
* @file        drvlib_gpio.c
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "drvlib_gpio.h"

char gpio_path[100];

int RB_fd;   //read ccm3310 rb  pin gpio  fd


int gpio_config(const char* attr, const char* val)
{
  char file_path[100];
  int len;
  int fd;

  sprintf(file_path, "%s/%s", gpio_path, attr);
  if (0 > (fd = open(file_path, O_WRONLY))) {
    perror("open error");
    return fd;
  }

  len = strlen(val);
  if (len != write(fd, val, len)) {
    perror("write error");
    close(fd);
    return -1;
  }

  close(fd);  //关闭文件
  return 0;
}

//------------------------------//

int config_RB_GPIO(void)
{
  int fd;

  /* 判断指定编号的GPIO是否导出 */
  sprintf(gpio_path, "/sys/class/gpio/gpio%s", RB_PIN_GPIO_NUM);

  DEBUG("gpio_path ： %s \n", gpio_path);


  if (access(gpio_path, F_OK)) {//如果目录不存在 则需要导出

    DEBUG("目录不存在 ,执行导出 \n");

    int len;

    if (0 > (fd = open("/sys/class/gpio/export", O_WRONLY))) {
      perror("open error");
    }

    len = strlen(RB_PIN_GPIO_NUM);
    if (len != write(fd, RB_PIN_GPIO_NUM, len)) {//导出gpio
      perror("write error");
      close(fd);
    }

    close(fd);  //关闭文件
  }

  /* 配置为输入模式 */
  if (gpio_config("direction", "in"))
  {
    DEBUG("gpio_config error");
  }

  /* 极性设置 */
  if (gpio_config("active_low", "0"))
  {
    DEBUG("gpio_config error");
  }

  /* 配置为非中断方式 */
  if (gpio_config("edge", "none"))
  {
    DEBUG("gpio_config error");
  }

}


/**
 * @brief
 * @details
 * @param[in]
 * @param[out]
 * @retval     0 : low_voltage  ;    1 : High_voltage
 * @par
 */
int getGpioValue()
{
  char file_path[100];
  char val;

  /* 读取GPIO电平状态 */
  sprintf(file_path, "%s/%s", gpio_path, "value");

  if (0 > (RB_fd = open(file_path, O_RDONLY))) {
    perror("open error");
  }  

  if (0 > read(RB_fd, &val, 1)) {
    DEBUG("read error");
    close(RB_fd);
  }

  //DEBUG("value: %c\n", val);

  close(RB_fd);

  if (val == '1')
    return 1;
  else if (val == '0')
    return 0;
  else
    return -1;
}



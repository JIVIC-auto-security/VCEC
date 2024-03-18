/**
* @file        drvlib_spi.h
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "drvlib_spi.h"


int spifd;                          // SPI 控制引脚的设备文件描述符

static uint32_t mode = SPI_MODE_3;      //用于保存 SPI 工作模式
static uint8_t bits = 8;                // 接收、发送数据位数
static uint32_t speed = 500000;         // 发送速度
static uint16_t delay;                  //保存延时时间




int transfer(int spifd, uint8_t const* tx, uint8_t const* rx, size_t len)
{
  int ret;

  struct spi_ioc_transfer tr = {
     .tx_buf = (unsigned long)tx,
     .rx_buf = (unsigned long)rx,
     .len = len,
     .delay_usecs = delay,
     .speed_hz = speed,
     .bits_per_word = bits,
  };

  ret = ioctl(spifd, SPI_IOC_MESSAGE(1), &tr);
  if (ret == -1)
  {
    return -1;
  }

  return 0;
}

int spi_init(void)
{
  int ret;
  spifd = open(spi_DEV_path, O_RDWR);
  if (spifd < 0)
  {
    perror("/dev/spidev1.0");
    return -1;
  }  

  //设置spi工作模式
  ret = ioctl(spifd, SPI_IOC_WR_MODE, &mode);
  //ret = ioctl(spifd, SPI_IOC_RD_MODE, &mode);
  if (ret == -1)
  {
    printf("SPI_IOC_RD_MODE error......\n ");
    goto fd_close;
  }
  ret = ioctl(spifd, SPI_IOC_RD_MODE, &mode);
  //ret = ioctl(spifd, SPI_IOC_WR_MODE, &mode);
  if (ret == -1)
  {
    printf("SPI_IOC_WR_MODE error......\n ");
    goto fd_close;
  }

  //printf("set mode %d \n ", mode);

  //设置SPI通信的字长

  ret = ioctl(spifd, SPI_IOC_WR_BITS_PER_WORD, &bits);
  if (ret == -1)
  {
    printf("SPI_IOC_WR_BITS_PER_WORD error......\n ");
    goto fd_close;
  }

  ret = ioctl(spifd, SPI_IOC_RD_BITS_PER_WORD, &bits);
  if (ret == -1)
  {
    printf("SPI_IOC_RD_BITS_PER_WORD error......\n ");
    goto fd_close;
  }

  //设置SPI最高工作频率
  ret = ioctl(spifd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
  if (ret == -1)
  {
    printf("SPI_IOC_WR_MAX_SPEED_HZ error......\n ");
    goto fd_close;
  }
  ret = ioctl(spifd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
  if (ret == -1)
  {
    printf("SPI_IOC_RD_MAX_SPEED_HZ error......\n ");
    goto fd_close;
  }


  //printf("spi mode: 0x%x\n", mode);
  //printf("bits per word: %d\n", bits);
  //printf("max speed: %d Hz (%d KHz)\n", speed, speed / 1000);

  return 0;

fd_close:

  close(spifd);
  return -1;
}





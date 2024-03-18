/**
* @file        drvlib_printf.c
* @brief
* @details
* @author
* @date
* @version     V1.0
* @par Copyright(c):
*/
#include "drvlib_printf.h"





/*******************************************************************************
*函 数 名：DEBUG
*功能说明：和printf 一样
*形   参：
*返 回 值：无
*******************************************************************************/
void DEBUG(char* fmt, ...)
{
	va_list args;       //定义一个va_list类型的变量，用来储存单个参数  
	va_start(args, fmt); //使args指向可变参数的第一个参数  
	vprintf(fmt, args);  //必须用vprintf等带V的  
	va_end(args);       //结束可变参数的获取
}
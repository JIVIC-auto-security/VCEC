/*****************************************************************************
 ** @FileName drvlib_bytes.h
 ** @EditBy   PLH
 ** @Version  V0.0.1
 ** @Date     2023-05-31
 ** @brief    
*****************************************************************************/
#ifndef _DRVLIB_BYTES_H_
#define _DRVLIB_BYTES_H_

#include "drvlib_type.h"


#define LO_NIB(b) ((b) & 0xF)
#define HI_NIB(b) ((b) >> 4)


//get uint16_t L H byte
#define LO_BYTE(w) ((uint8_t)(w))
#define HI_BYTE(w) ((uint8_t)((uint16_t)(w) >> 8))

#define LO_WORD(x) ((uint16_t)(x))
#define HI_WORD(x) ((uint16_t)((uint32_t)(x) >> 16))


//---------------------------------------------------------------------------------------------//

#define MAKE_WORD(lo,hi)  ((uint16_t)(((uint8_t)(lo))|(((uint16_t)((uint8_t)(hi)))<<8)))
#define MAKE_LONG(lo,hi)  ((uint32_t)(((uint16_t)(lo))|(((uint32_t)((uint16_t)(hi)))<<16)))


//uint64_t ´óÐ¡¶Ë×ª»»
#define sw64(A) ((uint64_t)(\
				(((uint64_t)(A)& (uint64_t)0x00000000000000ffULL) << 56) | \
				(((uint64_t)(A)& (uint64_t)0x000000000000ff00ULL) << 40) | \
				(((uint64_t)(A)& (uint64_t)0x0000000000ff0000ULL) << 24) | \
				(((uint64_t)(A)& (uint64_t)0x00000000ff000000ULL) << 8) | \
				(((uint64_t)(A)& (uint64_t)0x000000ff00000000ULL) >> 8) | \
				(((uint64_t)(A)& (uint64_t)0x0000ff0000000000ULL) >> 24) | \
				(((uint64_t)(A)& (uint64_t)0x00ff000000000000ULL) >> 40) | \
				(((uint64_t)(A)& (uint64_t)0xff00000000000000ULL) >> 56) ))


#endif

/************************ END OF THIS FILE ************************/

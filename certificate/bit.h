/*
* Conditions Of Use
*
* This software was developed by employees of the National Institute of
* Standards and Technology (NIST), and others.
* This software has been contributed to the public domain.
* Pursuant to title 15 United States Code Section 105, works of NIST
* employees are not subject to copyright protection in the United States
* and are considered to be in the public domain.
* As a result, a formal license is not needed to use this software.
*
* This software is provided "AS IS."
* NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
* OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
* AND DATA ACCURACY. NIST does not warrant or make any representations
* regarding the use of the software or the results thereof, including but
* not limited to the correctness, accuracy, reliability or usefulness of
* this software.
*/

/* Tony Cheneau <tony.cheneau@nist.gov> */

/*
 * Endianness conversion function
 */

#ifndef __TINYDTLS_BIT_H
#define __TINYDTLS_BIT_H

#include <stdint.h>

#define UINT32_TO_UINT8_BE(src, dst, index) \
    do { dst[index] = (src >> 24) & 0xff; \
         dst[index+1] = (src >> 16) & 0xff; \
         dst[index+2] = (src >> 8) & 0xff; \
         dst[index+3] = (src) & 0xff; \
    } while(0);

/**
 * @brief Convert a uint32_t array using host ordering to a uint8_t array using big endian ordering
 *
 * @param src array to convert
 * @param length length of src and dst (in byte)
 * @param dst array where the converted data is stored
 */
void uint32_array_to_uint8_be(uint32_t * src, int length, uint8_t * dst);


/**
 * @brief Convert a uint8_t array using big endian ordering in a uint32_t array using host ordering
 *
 * @param src array to convert
 * @param length length of src and dst (in byte)
 * @param dst array where the converted data is stored
 */
void uint8be_array_to_uint32_host(uint8_t * src, int length, uint32_t * dst);

#endif

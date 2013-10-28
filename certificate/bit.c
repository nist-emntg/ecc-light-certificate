#include "bit.h"

#if !defined(WITH_CONTIKI) && defined(HAVE_ASSERT_H)
#include <assert.h>
#else
#define assert(condition) do{} while(0)
#endif

void uint32_array_to_uint8_be(uint32_t * src, int length, uint8_t * dst)
{
	int i;

	assert(length % sizeof(uint32_t) == 0);

	for (i = 0; i < length / sizeof(uint32_t); i++)
	{
		UINT32_TO_UINT8_BE(src[i], dst, i * 4);
	}
}

void uint8be_array_to_uint32_host(uint8_t * src, int length, uint32_t * dst)
{
	int i, scale_f = sizeof(uint32_t) / sizeof(uint8_t);

	assert(length % sizeof(uint32_t) == 0);

	for (i = 0; i < length / scale_f; i++)
	{
		dst[i] = src[scale_f * i] << 24 |
		         src[scale_f * i + 1] << 16 |
		         src[scale_f * i + 2] << 8 |
		         src[scale_f * i + 3];
	}
}

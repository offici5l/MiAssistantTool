#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>
#include <stddef.h>

size_t b64_encodedLength(size_t length);

size_t b64_decodedLength(size_t length);

void b64_encode(uint8_t *src, size_t len, uint8_t *dst);

size_t b64_decode(uint8_t *src, size_t len, uint8_t *dst);

#endif

uint8_t charTable[64] = 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encodedLength(size_t length)
{
	return (length + 2) / 3 * 4;
}

size_t b64_decodedLength(size_t length)
{
	return length * 3 / 4;
}

void b64_encodeFirstByte(uint8_t *src, uint8_t *dst)
{
		*dst = charTable[(src[0] & 0xfc) >> 2]; 
		dst++;

		*dst = (src[0] & 0x03) << 4;
		*dst |= (src[1] & 0xf0) >> 4;
		*dst = charTable[*dst];
}

void b64_encode(uint8_t *src, size_t len, uint8_t *dst)
{
	while(len >= 3)
	{
		b64_encodeFirstByte(src, dst);
		dst += 2;

		*dst = (src[1] & 0x0f) << 2;
		*dst |= (src[2] & 0xc0) >> 6;
		*dst = charTable[*dst];
		dst++;

		*dst = charTable[src[2] & 0x3f];
		dst++;

		src += 3;
		len -= 3;
	}

	if(len == 2)
	{
		b64_encodeFirstByte(src, dst);
		dst += 2;

		*dst = '=';
	}
	else if(len == 1)
	{
		*dst = charTable[(src[0] & 0xfc) >> 2];
		dst++;

		*dst = charTable[(src[0] & 0x03) << 4];
		dst++;

		*dst = '=';
		dst++;

		*dst = '=';
	}
}

uint8_t lookupB64(uint8_t c)
{
	switch(c)
	{
		default:
		case 'A': return 0;
		case 'B': return 1;
		case 'C': return 2;
		case 'D': return 3;
		case 'E': return 4;
		case 'F': return 5;
		case 'G': return 6;
		case 'H': return 7;
		case 'I': return 8;
		case 'J': return 9;
		case 'K': return 10;
		case 'L': return 11;
		case 'M': return 12;
		case 'N': return 13;
		case 'O': return 14;
		case 'P': return 15;
		case 'Q': return 16;
		case 'R': return 17;
		case 'S': return 18;
		case 'T': return 19;
		case 'U': return 20;
		case 'V': return 21;
		case 'W': return 22;
		case 'X': return 23;
		case 'Y': return 24;
		case 'Z': return 25;
		case 'a': return 26;
		case 'b': return 27;
		case 'c': return 28;
		case 'd': return 29;
		case 'e': return 30;
		case 'f': return 31;
		case 'g': return 32;
		case 'h': return 33;
		case 'i': return 34;
		case 'j': return 35;
		case 'k': return 36;
		case 'l': return 37;
		case 'm': return 38;
		case 'n': return 39;
		case 'o': return 40;
		case 'p': return 41;
		case 'q': return 42;
		case 'r': return 43;
		case 's': return 44;
		case 't': return 45;
		case 'u': return 46;
		case 'v': return 47;
		case 'w': return 48;
		case 'x': return 49;
		case 'y': return 50;
		case 'z': return 51;
		case '0': return 52;
		case '1': return 53;
		case '2': return 54;
		case '3': return 55;
		case '4': return 56;
		case '5': return 57;
		case '6': return 58;
		case '7': return 59;
		case '8': return 60;
		case '9': return 61;
		case '+': return 62;
		case '/': return 63;
	}
}

void decode2(uint8_t *src, uint8_t *dst)
{
	*dst = lookupB64(src[0]) << 2;
	*dst |= (lookupB64(src[1]) & 0x30) >> 4;
}

void decode3(uint8_t *src, uint8_t *dst)
{
	decode2(src, dst);
	dst++;

	*dst = (lookupB64(src[1]) & 0x0f) << 4;
	*dst |= (lookupB64(src[2]) & 0x3c) >> 2;
}

void decode4(uint8_t *src, uint8_t *dst)
{
	decode3(src, dst);
	dst += 2;

	*dst = (lookupB64(src[2]) & 0x03) << 6;
	*dst |= lookupB64(src[3]);
}

size_t b64_decode(uint8_t *src, size_t len, uint8_t *dst)
{
	size_t dstLength = 0;

	while(len >= 5)
	{
		decode4(src, dst);
		dst += 3;
		src += 4;
		len -= 4;
		dstLength += 3;
	}
	
	if(len == 4)
	{
		if(src[3] != '=')
		{
			decode4(src, dst);
			dstLength += 3;
		} 
		else if(src[2] != '=')
		{
			decode3(src, dst);
			dstLength += 2;
		}
		else
		{
			decode2(src, dst);
			dstLength += 1;
		}
	}


	else if(len == 3)
	{
		decode3(src, dst);
		dstLength += 2;
	}
	else if(len == 2)
	{
		decode2(src, dst);
		dstLength += 1;
	}
	else
	{
		
	}

	return dstLength;
}
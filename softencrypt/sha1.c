#include "sha1.h"

void initsha1() {}
unsigned char* sha1Encrypt(const unsigned char* src, unsigned char* ensrc) {
	SHA1(src, strlen(src), ensrc);  
	return ensrc;
}
#ifndef KECCAKSPONGE_SHIM_H
#define KECCAKSPONGE_SHIM_H
int KeccakWidth1600_Sponge(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long outputByteLen);
#endif

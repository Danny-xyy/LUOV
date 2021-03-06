/*
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to SnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_SnP_h_
#define _KeccakP_1600_SnP_h_

//#include "../../../common/brg_endian.h"
//#include "../../KeccakP-1600/Optimized64/LCu6/KeccakP-1600-opt64-config.h"
#include "brg_endian.h"
#include "KeccakP-1600-opt64-config.h"


#define KeccakP1600_implementation      "generic 64-bit optimized implementation (" KeccakP1600_implementation_config ")"
#define KeccakP1600_stateSizeInBytes    200
#define KeccakP1600_stateAlignment      8
#define KeccakF1600_FastLoop_supported
#define KeccakP1600_12rounds_FastLoop_supported

#include <stddef.h>

#define KeccakP1600_StaticInitialize()
void KeccakP1600_Initialize(unsigned char *state);
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#define KeccakP1600_AddByte(state, byte, offset) \
    ((unsigned char*)(state))[(offset)] ^= (byte)
#else
void KeccakP1600_AddByte(unsigned char  *state, unsigned char data, unsigned int offset);
#endif
void KeccakP1600_AddBytes(unsigned char  *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteBytes(unsigned char  *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteWithZeroes(unsigned char  *state, unsigned int byteCount);
void KeccakP1600_Permute_Nrounds(unsigned char  *state, unsigned int nrounds);
void KeccakP1600_Permute_12rounds(unsigned char  *state);
void KeccakP1600_Permute_24rounds(unsigned char  *state);
void KeccakP1600_ExtractBytes(const unsigned char  *state, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_ExtractAndAddBytes(const unsigned char  *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
size_t KeccakF1600_FastLoop_Absorb(unsigned char  *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);
size_t KeccakP1600_12rounds_FastLoop_Absorb(unsigned char  *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);

#endif

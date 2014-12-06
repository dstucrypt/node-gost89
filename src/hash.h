#ifndef GOST89_HASH_H
#define GOST89_HASH_H

extern "C"
int compute_hash(const byte *buf, int buf_len, byte ret[32]);

#endif


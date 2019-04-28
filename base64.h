//
// Created by lievsim on 4/24/19.
//

#ifndef KIND_BASE64_H
#define KIND_BASE64_H

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);
void build_decoding_table();
void base64_cleanup();
int getEncodingLen(int inLen);

#endif //KIND_BASE64_H

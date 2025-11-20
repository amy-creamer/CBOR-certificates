#include 

int encode_c509_certificate(const C509Certificate *cert, uint8_t *out_buf, size_t buf_size, size_t *out_len){
    CborEncoder encoder, certArray, tbsArray;
}
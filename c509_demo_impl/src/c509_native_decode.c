/* C509 Certificate native encoder/decoder */

#include "../../tinycbor/src/cbor.h"
#include "cbor_struct.c"


int c509_certificate_decode(const uint8_t *cbor_data, size_t data_len, C509Certificate *cert){
    CborParser parser; //cbor buffer
    CborValue it,arr; //it is top level, arr is iterating thru arrays
    if (cbor_parser_init(cbor_data,data_len,0, &parser, &it)!= CborNoError) return -1; 
    //parser updates w pointer to buffer, length, internal flags/state
    
    if (cbor_value_enter_container(&it,&arr)!= CborNoError) return -1;

//
// need to add validation checks
//

    //certificate type
    int t;
    cbor_value_get_int(&cert, &t);
    cert->type = t;
    cbor_value_advance(&arr);

    //serial_number
    decode_biguint(&arr, &out->serial_number)

}

CborError decode_biguint(CborValue *it, BigUint *out){
    out->len = 0;

    if (cbor_value_is_unsigned_integer(it)){
        uint64_t val;
        cbor_value_get_uint64(it,&v);
        if (v==0){
            if (BIGUINT_MAX_LEN < 1){ // how long is a serial number
                return CborErrorDataTooLarge
            } 
            out->data[0]=0;
            out->len=1;
            return CborNoError
        }

        size_t num_bytes = 0;
        uint64_t t = v;
        while (tmp > 0) {
            num_bytes++;
            tmp >>=8;
        }

        if (num_bytes > BIGUINT_MAX_LEN){
            return CborErrorDataTooLarge;
        }

        out->len = num_bytes;

        //big endian
        //remove this
        //0x12345678 -> 0x00123456 and 0x78 
        //0x78 -> 0x5678 -> ...
        for (size_t i = 0; i<nbytes;i++){
            out->data[num_bytes-1-i]=(uint8_t)(v & 0xFF);
            v>>>=8
        } //taking least sig byte first, and working backwards

        return CborNoError;
    }

}


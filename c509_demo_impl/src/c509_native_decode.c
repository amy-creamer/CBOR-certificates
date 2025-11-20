/* C509 Certificate native encoder/decoder */

#include "../../tinycbor/src/cbor.h"


int c509_certificate_decode(const uint8_t *cbor_data, size_t data_len, C509Certificate *cert){
    CborParser parser;
    CborValue it,arr;
    if (cbor_parser_init(cbor_data,data_len,0, &parser, &it)!= CborNoError) return -1; 

    if (cbor_value_enter_container(&it,&arr)!= CborNoError) return -1;

//
// need to add validation checks
//

    //certificate type
    int t;
    cbor_value_get_int(&certArray, &t);
    cert->type = t;
    cbor_value_advance(&arr);




}
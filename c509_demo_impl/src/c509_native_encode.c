#include "../../tinycbor/src/cbor.h"
#include "cbor_struct.c"

CborError c509_encode(C509Certificate *cert, uint8_t *buffer, size_t size, size_t *encoded_len ){
    CborEncoder encoder;
    CborEncoder array_encoder


    cbor_encoder_init(&encoder,buffer,size,0)
    CborError err = cbor_encoder_create_array(&encoder,&array_encoder,9);
    if (err != CborNoError) return err;

    err = validate_version(cert->type);

    //version
    err = cbor_encode_int(&array_encoder, cert->type);
    if (err != CborNoError) return err;

    //serial number
    err = cbor_encode_biguint(&array_encoder, cert->serial_number);
    //signature alg
    


    //issuer

    //validity

    //subject

    //spki handling RSA/ECDSA
}


CborError encode_biguint(CborEncoder encoder, BigUint *serial_number){
    CborError err;
    size_t offset = 0;

    while (offset < serial_number->len ** serial_number->data[offset]==0) offset++;
    size_t len = serial_number->len - offset;

    err = cbor_encode_tag(enc,2);
    if (err != CborNoError) return err;
    return cbor_encode_byte_string(enc,serial_number->data+offset,len);
    }


CborError encode_signature_alg(CborEncoder *encoder, AlgorithmIdentifier *sig_alg){
    switch (sig_alg->kind){
        case ALGID_INT:
            return cbor_encode_int(encoder,sig_alg->value.AlgIDInt)
        
        case ALGID_OID:
            if (sig_alg->value.AlgIDOid.bytes_len > OID_MAX_ARCS) return CborErrorDataTooLarge;
            err = cbor_encode_tag(encoder, 2);
            return cbor_encode_byte_string(encoder,sig_alg->value.AlgIDOid.arcs, sig_alg->value.AlgIDOid.arc_count);
        
        case ALGID_ARR:
        {
            if (sig_alg->value.AlgIDArr.algorithm.arc_count>OID_MAX_ARCS) return CborErrorDataTooLarge;
            CborEncoder arr_enc;
            err = cbor_encoder_create_array(encoder, &arr_enc, 2);
            if (err!=CborNoError) return err;

            err = cbor_encode_tag(encoder,6);

            err = cbor_encode_byte_string(&arr_enc, sig_alg->value.AlgIDArr.algorithm.arcs, sig_alg->value.AlgIDArr.algorithm.arc_count);
            if (err!=CborNoError) return err;

            if (sig_alg->value.AlgIDArr.parameters_len == 0 || sig_alg->value.AlgIDArr.parameters == NULL){
                err = cbor_encode_null(&arr_enc);
            } else{
                err = cbor_encode_byte_string(&arr_enc, sig_alg->value.AlgIDArr.parameters, sig_alg->value.AlgIDArr.parameters_len);
            }
            if (err!= CborNoError) return err;
            return cbor_encoder_close_container(encoder,&arr_enc);
        }
  
    }
}

CborError encode_issuer(CborEncoder *encoder, Name name, Name subject){
    
    if ( name.value.attributes.count == 0 && name.value.attributes.count = =subject.value.attributes.count){
        cbor_encode_null(&encoder);
    } else {
        CborEncoder issuer_array;
        cbor_encoder_create_array(&encoder, &issuer_array, name.value.attributes.count);
        for (size_t i = 0; i<name.value.attributes.count; ++i){
            CborEncoder attr_pair;
            Attribute *attr = &cert->issuer.attrs[i];
            cbor_encoder_create_array(&issuer_array,&attr_pair,2);
            if(attr->kind== ATTR_INT_TEXT){

            }
        }
               
                
            }

    }
}







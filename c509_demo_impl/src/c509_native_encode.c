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

CborError encode_issuer(CborEncoder *encoder, Name name){
    
    
    CborEncoder issuer_array;
    cbor_encoder_create_array(&encoder, &issuer_array, name.value.attributes.count);
    for (size_t i = 0; i<name.value.attributes.count; ++i){
        CborEncoder attr_pair;
        Attribute *attr = &cert->issuer.attrs[i];
        cbor_encoder_create_array(&issuer_array,&attr_pair,2);
        if(attr->kind == ATTR_INT_TEXT && ->value.intText.attributeType_int!=0){
            cbor_encode_int(&attr_pair,attr->value.intText.attributeType_int);
            cbor_encode_text_string(&attr_pair,(const char*)attr->value.intText.attributeValue_text, attr->value.intText.attributeValue_text.value.bytes.len);
        } else {
            cbor_encode_tag(&attr_pair,6);
            cbor_encode_byte_string(&attr_pair,attr->value.oidBytes.attributeType_oid.arcs,attr->value.oidBytes.bytes_len);
            cbor_encode_text_String(&attr_pair,attr->value.oidBytes.attributeType_oid.arcs, &attr->value.oidBytes.bytes_len);
        }
        cbor_encoder_closer_container(&issuer_array,&attr_pair);
    }
    cbor_encoder_close_container(&encoder,&issuer_array);
            
                
            

    }

CborError encode_validity_before(CborEncoder *encoder, ValidityNotBefore validity){
    cbor_encode_tag(encoder,1);
    cbor_encode_uint(&encoder,validity

}

CborError encode_validity_after(CborEncoder encoder, ValidityNotAfter validity){
    if (validity == uINT64_MAX){

        cbor_encode_null(&encoder);
    } else{
        cbor_encode_tag(&encoder,1);
        cbor_encode_uint(&encoder,validity);
    }
    

}

CborError encode_spka(CborEncoder *encoder, SubjectPubKeyInfo subject_pub_alg){
    err = encode_signature_alg(encoder, subject_pub_alg.algorithm);
    if (err!=CborNoError) return err;

    if (subject_pub_alg.key == PUBKEY_RSA){
        if (subject_pub_alg.key_data.rsa == 0 || (subject_pub_alg.key_data.rsa.exponent_len == 3 && subject_pub_alg.key_data.rsa.exponent[0] == 0x01 && subject_pub_alg.key_data.rsa.exponent[1] == 0x00 && subject_pub_alg.key_data.rsa.exponent[2] == 0x01)){
            cbor_encode_tag(&encoder,2);
            cbor_encode_byte_string(&encoder, subject_pub_alg.key_data.rsa.modulus, subject_pub_alg.key_data.rsa.modulus_len);
        }else{
            
        }

    }
}








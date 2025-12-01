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

    //serial number
    decode_biguint(&arr, &cert->serial_number)
    cbor_value_advance(&arr);

    //algorithm identifier
    decode_algorithm_identifier(&arr,&cert->issuer_sig_alg)
    cbor_value_advance(&arr);

    //issuer
    decode_issuer(&arr,&cert->issuer);
    cbor_value_advance(&arr);

    //validity
    decode_validity(&arr,&cert->validity);
    cbor_value_advance(&arr);

    //pubkey alg
    decode_spk_alg(&arr,&cert->subj_pubkey_alg);
    cbor_value_advance(&arr);

    //pubkey
    decode_spk_info(&arr,&cert->subj_pubkey);
    cbor_value_advance(&arr);

    //extensions
    decode_extensions(&arr,&cert->*extensions,&cert->extensions_count);

}

CborError decode_oid(CborValue *it, Oid *out){
    out->arc_count = 0;
    if (!cbor_value_is_byte_string(it)){
        return CborErrorIllegalType;
    }

    size_t len = 0
    cbor_value_calculate_string_length(it, &len);

    if (len==0 || len >OID_MAX_BYTES){
        return CborErrorDataTooLarge;
    }

    uint8_t buf[OID_MAX_BYTES]; //stack
    size_t c_len = len;
    cbor_value_copy_byte_string(it,buf,&c_len,NULL);

    size_t pos = 0;
    uint8_t first = buf[pos++];
    uint32_t arc0 = first /40; //as according to DER-encoded OID bytes
    uint32_t arc1 = first % 40;

    if (oid->arc_count + 2>OID_MAX_ARCS){
        return CborErrorDataTooLarge;
    }

    oid->arcs[0] = arc0;
    oid->arcs[1] = arc1;
    oid->arc_count = 2;

    while (pos<len){
        uint32_t val = 0;
        for (;;){
            if (pos>=len){
                return CborErrorUnexpectedEOF;
            }

            uint8_t byte = buf[pos++];
            value = (value<<6) | (byte & 0x7f);

            if ((byte & 0x80) == 0){ //last byte
                break
            }
        }
        
        if (oid->arc_count >= OID_MAX_ARCS){
            return CborErrorDataTooLarge;
        }
        oid->arcs[oid->arc_count++] = value;
    }
    return CborNoError
    
}

CborError decode_biguint(CborValue *it, BigUint *out){
    out->len = 0;

    //bytestring
    if (cbor_value_is_byte_string(it)){
        size_t len = 0;

        cbor_value_calculate_string_length(it,&len)

        if (len > BIGUINT_MAX_LEN){
            return CborErrorDataTooLarge;
        }

        size_t c_len = len;
        cbor_value_copy_byte_string(it,out->data,&copy_len,NULL);
        
    
        out->len = c_len;

        while (out->len > 1 && out->data[0]=0x00){
            memmove(out->data,out->data+1,out->len-1);
            out->len--;
        }
        return CborNoError;
    }
    
    return CborErrorIllegalType;
}

CborError decode_algorithm_identifier(CborValue *it, AlgorithmIdentifier *out){
    CborType t = cbor_value_get_type(it);

    if (t==CborIntegerType){
        out->kind = ALGID_INT;
        int v;
        cbor_value_get_int(it,&v);
        out->value.AlgIDInt = v;
        return CborNoError;
    }

    if (t==CborTagType){
        out->kind = ALGID_OID;
        CborTag tag;
        cbor_value_get_tag(it,&tag);
        cbor_value_advance_fixed(it);
        return decode_oid(it,&out->value.AlgIDOid);
    }

    if (t==CborArrayType){
        CborValue arr;
        out->kind = ALGID_ARR;
        cbor_value_enter_container(it,&arr);

        //element 0: OID
        decode_oid(&arr,&alg->value.AlgIDArr.algorithm);
        cbor_value_advance(&arr);
        
        //element 1: parameters 
        if (!cbor_value_at_end(&arr)){
            size_t len;
            //allocate parameters buffer and copy
            len = out->value.AlgIDArr.parameters_len;
            cbor_value_copy_byte_string(&arr, alg->value.AlgIDArr.parameters,&len,&arr);

        }
        return cbor_value_leave_container(it,&arr);

    }
    return CborErrorIllegalType;

}

CborError decode_name(CborValue *it, Name *out){
    CborType t = cbor_value_get_type(it);
    CborError e;

    if (t==CborArrayType){
        CborValue arr;
        out->kind = NAME_ATTR;
        out->Value.attributes.count = 0;
        err=cbor_value_enter_container(it,&arr);
        if (err!=CborNoError) return err;

        //while processing list
        while (!cbor_value_at_end(&arr)){
            //overflow 
            if (out->Value.attributes.count>=MAX_ATTRIBUTES){
                return CborErrorDataTooLarge;
            }
            Attribute *slot = &out->Value.attributes.items[out->Value.attributes.count];

            err = decode_attribute(&arr,&out->Value.attributes);
            if (err!=CborNoError) return err;
            out->Value.attributes.count++;
            err=cbor_value_advance(&arr);
            if (err!=CborNoError) return err;
        }
        
        return cbor_value_leave_container(it,&arr);



    }
    if (t==CborTextStringType || t==CborByteStringType || t = CborTagType){
        out->kind=NAME_SPECIALTEXT;
        if (t==CborTextStringType){
            size_t len = sizeof(out->Value.special.value);
            err=cbor_value_copy_text_string(it,out->Value.text,&len,NULL);
            return err;
        }

        if (t==CborByteStringType){
            size_t len = sizeof(out->Value.special.value);
            err=cbor_value_copy_byte_string(it,out->Value.special.value,&len, NULL);
            if (err!=CborNoError) return err;
            return CborNoError;

        }

        if (t==CborTagType){
            CborTag tag;
            err = cbor_value_get_tag(it,&tag);

            if(err!=CborNoError) return err;
            return CborNoError;
          

        }
  
    }

   
    return CborErrorIllegalType;
}

CborError decode_validity(CborValue *it, Validity *out){
    CborType t = cbor_value_get_type(it);
    if 
}

CborError decpde_spk_info(CborValue *it, SubjectPubKeyInfo *out){
    CborType t = cbor_value_get_type(it)

}

CborError decode_spk_alg(CborValue *it, Defined *out){
    CborType t = cbor_value_get_type(it);
    if (t == CborNullType){
        return CborErrorIllegalType;
    }

}
/

CborError decode_extensions(CborValue *it, Extensions *out)


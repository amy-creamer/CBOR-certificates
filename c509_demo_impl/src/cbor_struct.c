#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
//constants
#define BIGUINT_MAX_LEN 64

//enums
typedef enum{ ATTR_INT_TEXT, ATTR_OID_BYTES} AttributeType;

typedef enum{SPECIALTEXT_TEXT,SPECIALTEXT_OID,SPECIALTEXT_BYTES} SpecialTextType;

typedef enum {NAME_ATTR,NAME_SPECIALTEXT}NameType;

typedef enum {ALGID_INT,ALGID_OID,ALGID_ARR}AlgorithmIdentifierType;
//ALGID_ARR is OID with params (an array)
typedef enum{EXTENSION_INT,EXTENSION_OID}ExtensionType;

typedef enum{EXTENSIONS_LIST,EXTENSIONS_INT}ExtensionsType;

// PK algs
typedef enum {
    ALG_RSA,
    ALG_EC,
    ALG_X, //montgomery
    ALG_ED25519, //twisted edwards
    ALG_ED448 //edwards
} PKAlgorithmType;

typedef enum {
    DEF_INT,
    DEF_UINT,
    DEF_NEGINT,
    DEF_BYTES,
    DEF_TEXT,
    DEF_ARRAY,
    DEF_MAP,
    DEF_BOOL,
    DEF_NULL,
    DEF_FLOAT, //can be extended
} DefinedType;

typedef struct {
    uint8_t *data;
    size_t len;
} BigUint;

typedef struct {
    uint32_t *arcs;
    size_t arc_count;
} Oid;

struct Defined; 

typedef struct {
    struct Defined *items;
    size_t count;
} DefinedArray;

typedef struct {
    char *key;              
    struct Defined value;
} DefinedMapEntry;

typedef struct {
    DefinedMapEntry *entries;
    size_t count;
} DefinedMap;

typedef struct Defined {
    DefinedType type;

    union {
        uint64_t uint_val;
        int64_t int_val;
        int64_t negint_val;    
        struct {
            uint8_t *data;
            size_t len;
        } bytes_val;

        char *text_val;

        bool bool_val;

        double float_val;

        DefinedArray array_val;
        DefinedMap map_val;
    } value;

} Defined;



//Attribute
typedef struct {
    int attributeType_int;
    char *attributeValue_text;
} AttributeInt;

typedef struct {
    Oid attributeType_oid;
    uint8_t *attributeValue_bytes;
    size_t bytes_len;
} AttributeOid;


typedef struct {
    AttributeType kind;
    union{
        AttributeInt intText;
        AttributeOid oidBytes;
    } value;
} Attribute;

//AlgorithmIdentifier

typedef struct{
    Oid algorithm;
    uint8_t *parameters;
    size_t parameters_len;

} OidWithParams;

typedef struct{
    AlgorithmIdentifierType kind;
    union{
        int AlgIDInt;
        Oid AlgIDOid;
        OidWithParams AlgIDArr;
    } value;
} AlgorithmIdentifier;

typedef struct {
    AlgorithmIdentifier algorithm;
    // From C509 Draft list of PK algorithms types
    enum{
        PUBKEY_RSA,
        PUBKEY_EC,
        PUBKEY_X,
        PUBKEY_ED,
    } key;

    union {
        //RSA
        struct{
            uint8_t *modulus;
            size_t modulus_len;

            uint8_t *exponent;
            size_t exponent_len;
        } rsa;

        //EC where OID needed
        struct{
            const uint8_t *compressed_point;
            size_t point_len;
            Oid curve_oid;
        } ec;

        struct{
            const uint8_t *coord; //coor
            size_t coord_len;

        } ec_montgomery;

        struct{
            const uint8_t *public_key;
            size_t key_len;
        } ec_edwards;
    }key_data
} SubjectPubKeyInfo;


//Name
typedef struct {
    SpecialTextType kind;
    union{ 
        char *text;
        Oid oid;
        struct {
            uint8_t *data;
            size_t len;
        } bytes;
    } value;
} SpecialText;

typedef struct { //Name n; n.kind = NAME_ATTR n.value.attributes.items = malloc...
    NameType kind;

    union {
        struct{
            Attribute *items;
            size_t count;
        } attributes;

        SpecialText special;
    } Value;
} Name;


// Extensions

typedef struct {
    ExtensionsType kind;
    union{
        struct {
            Extension *items;
            size_t count;
        }extensionsList;
        int extensionsInt;
    } value;
} Extensions;

typedef struct {
    ExtensionType kind;

    union {
        struct {
            int extensionID;
            Defined extensionValue;
        } extension_int;

        struct {
            Oid extensionID;        
            bool critical;          
            uint8_t *extensionValue;
            size_t extensionValue_len;
        } extension_oid;
    } value;
} Extension;

typedef struct{
    bool has_expiry;
    uint64_t epoch_time;
} Time;

typedef struct{
    Time not_before;
    Time not_after;
} Validity;

typedef struct {
    //TBSCertificate
    int type;
    BigUint serial_number;
    AlgorithmIdentifier issuer_sig_alg;
    Name issuer;
    Validity validity;
    Name subject;
    SubjectPubKeyInfo subj_pubkey_alg;
    Defined subj_pubkey;
    Extensions *extensions;
    size_t extensions_count;

    //IssuerSignatureValue
    uint8_t *signature; size_t signature_len;   
} C509Certificate;


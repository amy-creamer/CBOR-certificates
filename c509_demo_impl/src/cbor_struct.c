#include <cstdint>


// ENUMS
typedef enum{
    ATTR_INT_TEXT,
    ATTR_OID_BYTES
} AttributeType;

typedef enum{
    SPECIALTEXT_TEXT,
    SPECIALTEXT_OID,
    SPECIALTEXT_BYTES
} SpecialTextType;

typedef enum {
    NAME_ATTR,
    NAME_SPECIALTEXT
}NameType;

typedef enum {
    ALGID_INT,
    ALGID_OID,
    ALGID_ARR
}AlgorithmIdentifierType;

typedef enum{
    EXTENSION_INT,
    EXTENSION_OID
}ExtensionType;

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
    uint_t *attributeValue_bytes;
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
} Extension

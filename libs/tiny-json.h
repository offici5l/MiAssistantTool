#include <string.h>
#include <ctype.h>

#ifndef _TINY_JSON_H_
#define	_TINY_JSON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define json_containerOf( ptr, type, member ) \
    ((type*)( (char*)ptr - offsetof( type, member ) ))

typedef enum {
    JSON_OBJ, JSON_ARRAY, JSON_TEXT, JSON_BOOLEAN,
    JSON_INTEGER, JSON_REAL, JSON_NULL
} jsonType_t;

typedef struct json_s {
    struct json_s* sibling;
    char const* name;
    union {
        char const* value;
        struct {
            struct json_s* child;
            struct json_s* last_child;
        } c;
    } u;
    jsonType_t type;
} json_t;


json_t const* json_create( char* str, json_t mem[], unsigned int qty );

static inline char const* json_getName( json_t const* json ) {
    return json->name;
}

static inline char const* json_getValue( json_t const* property ) {
    return property->u.value;
}

static inline jsonType_t json_getType( json_t const* json ) {
    return json->type;
}

static inline json_t const* json_getSibling( json_t const* json ) {
    return json->sibling;
}

json_t const* json_getProperty( json_t const* obj, char const* property );

char const* json_getPropertyValue( json_t const* obj, char const* property );

static inline json_t const* json_getChild( json_t const* json ) {
    return json->u.c.child;
}

static inline bool json_getBoolean( json_t const* property ) {
    return *property->u.value == 't';
}

static inline int64_t json_getInteger( json_t const* property ) {
  return strtoll( property->u.value,(char**)NULL, 10);
}

static inline double json_getReal( json_t const* property ) {
  return strtod( property->u.value,(char**)NULL );
}

typedef struct jsonPool_s jsonPool_t;
struct jsonPool_s {
    json_t* (*init)( jsonPool_t* pool );
    json_t* (*alloc)( jsonPool_t* pool );
};

json_t const* json_createWithPool( char* str, jsonPool_t* pool );



#ifdef __cplusplus
}
#endif

#endif	

typedef struct jsonStaticPool_s {
    json_t* mem;      /**< Pointer to array of json properties.      */
    unsigned int qty; /**< Length of the array of json properties.   */
    unsigned int nextFree;  /**< The index of the next free json property. */
    jsonPool_t pool;
} jsonStaticPool_t;

json_t const* json_getProperty( json_t const* obj, char const* property ) {
    json_t const* sibling;
    for( sibling = obj->u.c.child; sibling; sibling = sibling->sibling )
        if ( sibling->name && !strcmp( sibling->name, property ) )
            return sibling;
    return 0;
}

char const* json_getPropertyValue( json_t const* obj, char const* property ) {
	json_t const* field = json_getProperty( obj, property );
	if ( !field ) return 0;
        jsonType_t type = json_getType( field );
        if ( JSON_ARRAY >= type ) return 0;
	return json_getValue( field );
}

static char* goBlank( char* str );
static char* goNum( char* str );
static json_t* poolInit( jsonPool_t* pool );
static json_t* poolAlloc( jsonPool_t* pool );
static char* objValue( char* ptr, json_t* obj, jsonPool_t* pool );
static char* setToNull( char* ch );
static bool isEndOfPrimitive( char ch );

json_t const* json_createWithPool( char *str, jsonPool_t *pool ) {
    char* ptr = goBlank( str );
    if ( !ptr || (*ptr != '{' && *ptr != '[') ) return 0;
    json_t* obj = pool->init( pool );
    obj->name    = 0;
    obj->sibling = 0;
    obj->u.c.child = 0;
    ptr = objValue( ptr, obj, pool );
    if ( !ptr ) return 0;
    return obj;
}

json_t const* json_create( char* str, json_t mem[], unsigned int qty ) {
    jsonStaticPool_t spool;
    spool.mem = mem;
    spool.qty = qty;
    spool.pool.init = poolInit;
    spool.pool.alloc = poolAlloc;
    return json_createWithPool( str, &spool.pool );
}

static char getEscape( char ch ) {
    static struct { char ch; char code; } const pair[] = {
        { '\"', '\"' }, { '\\', '\\' },
        { '/',  '/'  }, { 'b',  '\b' },
        { 'f',  '\f' }, { 'n',  '\n' },
        { 'r',  '\r' }, { 't',  '\t' },
    };
    unsigned int i;
    for( i = 0; i < sizeof pair / sizeof *pair; ++i )
        if ( pair[i].ch == ch )
            return pair[i].code;
    return '\0';
}

static unsigned char getCharFromUnicode( unsigned char const* str ) {
    unsigned int i;
    for( i = 0; i < 4; ++i )
        if ( !isxdigit( str[i] ) )
            return '\0';
    return '?';
}

static char* parseString( char* str ) {
    unsigned char* head = (unsigned char*)str;
    unsigned char* tail = (unsigned char*)str;
    for( ; *head; ++head, ++tail ) {
        if ( *head == '\"' ) {
            *tail = '\0';
            return (char*)++head;
        }
        if ( *head == '\\' ) {
            if ( *++head == 'u' ) {
                char const ch = getCharFromUnicode( ++head );
                if ( ch == '\0' ) return 0;
                *tail = ch;
                head += 3;
            }
            else {
                char const esc = getEscape( *head );
                if ( esc == '\0' ) return 0;
                *tail = esc;
            }
        }
        else *tail = *head;
    }
    return 0;
}

static char* propertyName( char* ptr, json_t* property ) {
    property->name = ++ptr;
    ptr = parseString( ptr );
    if ( !ptr ) return 0;
    ptr = goBlank( ptr );
    if ( !ptr ) return 0;
    if ( *ptr++ != ':' ) return 0;
    return goBlank( ptr );
}

static char* textValue( char* ptr, json_t* property ) {
    ++property->u.value;
    ptr = parseString( ++ptr );
    if ( !ptr ) return 0;
    property->type = JSON_TEXT;
    return ptr;
}

static char* checkStr( char* ptr, char const* str ) {
    while( *str )
        if ( *ptr++ != *str++ )
            return 0;
    return ptr;
}

static char* primitiveValue( char* ptr, json_t* property, char const* value, jsonType_t type ) {
    ptr = checkStr( ptr, value );
    if ( !ptr || !isEndOfPrimitive( *ptr ) ) return 0;
    ptr = setToNull( ptr );
    property->type = type;
    return ptr;
}

static char* trueValue( char* ptr, json_t* property ) {
    return primitiveValue( ptr, property, "true", JSON_BOOLEAN );
}

static char* falseValue( char* ptr, json_t* property ) {
    return primitiveValue( ptr, property, "false", JSON_BOOLEAN );
}

static char* nullValue( char* ptr, json_t* property ) {
    return primitiveValue( ptr, property, "null", JSON_NULL );
}

static char* expValue( char* ptr ) {
    if ( *ptr == '-' || *ptr == '+' ) ++ptr;
    if ( !isdigit( (int)(*ptr) ) ) return 0;
    ptr = goNum( ++ptr );
    return ptr;
}

static char* fraqValue( char* ptr ) {
    if ( !isdigit( (int)(*ptr) ) ) return 0;
    ptr = goNum( ++ptr );
    if ( !ptr ) return 0;
    return ptr;
}

static char* numValue( char* ptr, json_t* property ) {
    if ( *ptr == '-' ) ++ptr;
    if ( !isdigit( (int)(*ptr) ) ) return 0;
    if ( *ptr != '0' ) {
        ptr = goNum( ptr );
        if ( !ptr ) return 0;
    }
    else if ( isdigit( (int)(*++ptr) ) ) return 0;
    property->type = JSON_INTEGER;
    if ( *ptr == '.' ) {
        ptr = fraqValue( ++ptr );
        if ( !ptr ) return 0;
        property->type = JSON_REAL;
    }
    if ( *ptr == 'e' || *ptr == 'E' ) {
        ptr = expValue( ++ptr );
        if ( !ptr ) return 0;
        property->type = JSON_REAL;
    }
    if ( !isEndOfPrimitive( *ptr ) ) return 0;
    if ( JSON_INTEGER == property->type ) {
        char const* value = property->u.value;
        bool const negative = *value == '-';
        static char const min[] = "-9223372036854775808";
        static char const max[] = "9223372036854775807";
        unsigned int const maxdigits = ( negative? sizeof min: sizeof max ) - 1;
        unsigned int const len = ( unsigned int const ) ( ptr - value );
        if ( len > maxdigits ) return 0;
        if ( len == maxdigits ) {
            char const tmp = *ptr;
            *ptr = '\0';
            char const* const threshold = negative ? min: max;
            if ( 0 > strcmp( threshold, value ) ) return 0;
            *ptr = tmp;
        }
    }
    ptr = setToNull( ptr );
    return ptr;
}

static void add( json_t* obj, json_t* property ) {
    property->sibling = 0;
    if ( !obj->u.c.child ){
	    obj->u.c.child = property;
	    obj->u.c.last_child = property;
    } else {
	    obj->u.c.last_child->sibling = property;
	    obj->u.c.last_child = property;
    }
}

static char* objValue( char* ptr, json_t* obj, jsonPool_t* pool ) {
    obj->type    = *ptr == '{' ? JSON_OBJ : JSON_ARRAY;
    obj->u.c.child = 0;
    obj->sibling = 0;
    ptr++;
    for(;;) {
        ptr = goBlank( ptr );
        if ( !ptr ) return 0;
        if ( *ptr == ',' ) {
            ++ptr;
            continue;
        }
        char const endchar = ( obj->type == JSON_OBJ )? '}': ']';
        if ( *ptr == endchar ) {
            *ptr = '\0';
            json_t* parentObj = obj->sibling;
            if ( !parentObj ) return ++ptr;
            obj->sibling = 0;
            obj = parentObj;
            ++ptr;
            continue;
        }
        json_t* property = pool->alloc( pool );
        if ( !property ) return 0;
        if( obj->type != JSON_ARRAY ) {
            if ( *ptr != '\"' ) return 0;
            ptr = propertyName( ptr, property );
            if ( !ptr ) return 0;
        }
        else property->name = 0;
        add( obj, property );
        property->u.value = ptr;
        switch( *ptr ) {
            case '{':
                property->type    = JSON_OBJ;
                property->u.c.child = 0;
                property->sibling = obj;
                obj = property;
                ++ptr;
                break;
            case '[':
                property->type    = JSON_ARRAY;
                property->u.c.child = 0;
                property->sibling = obj;
                obj = property;
                ++ptr;
                break;
            case '\"': ptr = textValue( ptr, property );  break;
            case 't':  ptr = trueValue( ptr, property );  break;
            case 'f':  ptr = falseValue( ptr, property ); break;
            case 'n':  ptr = nullValue( ptr, property );  break;
            default:   ptr = numValue( ptr, property );   break;
        }
        if ( !ptr ) return 0;
    }
}

static json_t* poolInit( jsonPool_t* pool ) {
    jsonStaticPool_t *spool = json_containerOf( pool, jsonStaticPool_t, pool );
    spool->nextFree = 1;
    return spool->mem;
}

static json_t* poolAlloc( jsonPool_t* pool ) {
    jsonStaticPool_t *spool = json_containerOf( pool, jsonStaticPool_t, pool );
    if ( spool->nextFree >= spool->qty ) return 0;
    return spool->mem + spool->nextFree++;
}

static bool isOneOfThem( char ch, char const* set ) {
    while( *set != '\0' )
        if ( ch == *set++ )
            return true;
    return false;
}

static char* goWhile( char* str, char const* set ) {
    for(; *str != '\0'; ++str ) {
        if ( !isOneOfThem( *str, set ) )
            return str;
    }
    return 0;
}

static char const* const blank = " \n\r\t\f";

static char* goBlank( char* str ) {
    return goWhile( str, blank );
}

static char* goNum( char* str ) {
    for( ; *str != '\0'; ++str ) {
        if ( !isdigit( (int)(*str) ) )
            return str;
    }
    return 0;
}

static char const* const endofblock = "}]";

static char* setToNull( char* ch ) {
    if ( !isOneOfThem( *ch, endofblock ) ) *ch++ = '\0';
    return ch;
}

static bool isEndOfPrimitive( char ch ) {
    return ch == ',' || isOneOfThem( ch, blank ) || isOneOfThem( ch, endofblock );
}
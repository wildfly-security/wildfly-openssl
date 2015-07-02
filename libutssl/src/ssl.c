#include "utssl.h"
#include <jni.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
/* openssl is deprecated on OSX
   this pragma directive is requires to build it
   otherwise -Wall -Werror fail the build
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

typedef struct {
    BIO* in;
    BIO* out;
} ssl_engine;

#define CHECK_INIT() if(ssl_initialized == 0) {throwIllegalStateException(env, "OpenSSL has not been initalized"); return 0;}


static int ssl_initialized = 0;
static jclass byteArrayClass, stringClass;

static jint throwIllegalStateException( JNIEnv *env, char *message )
{
    jclass exClass;
    char *className = "java/lang/IllegalStateException";

    exClass = (*env)->FindClass( env, className);
    return (*env)->ThrowNew( env, exClass, message );
}

/**
 * Creates the SSL engine
 */
JNIEXPORT jlong JNICALL UT_OPENSSL(makeEngine) (JNIEnv *env) {
    CHECK_INIT();
    ssl_engine* engine = malloc(sizeof(ssl_engine));
    
    return (jlong)engine;
}

JNIEXPORT jint JNICALL UT_OPENSSL(initialize) (JNIEnv *env) {
    int version = SSLeay();
    printf("OpenSSL version %d \n", version);
    jclass clazz;
    jclass sClazz;

    /* Check if already initialized */
    if (ssl_initialized++) {
        return 0;
    }
    if (version < 0x0090700L) {
        ssl_initialized = 0;
        return throwIllegalStateException(env, "Invalid OpenSSL Version");
    }
    /* We must register the library in full, to ensure our configuration
     * code can successfully test the SSL environment.
     */
    CRYPTO_malloc_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_load_builtin_engines();
#endif
    OPENSSL_load_builtin_modules();

    //TODO: initialise threads

    //TODO: engine support?

    /* Cache the byte[].class for performance reasons */
    clazz = (*env)->FindClass(env, "[B");
    byteArrayClass = (jclass) (*env)->NewGlobalRef(env, clazz);

    /* Cache the String.class for performance reasons */
    sClazz = (*env)->FindClass(env, "java/lang/String");
    stringClass = (jclass) (*env)->NewGlobalRef(env, sClazz);

    return (jint)0;
}

//temp
JNIEXPORT jint JNICALL UT_OPENSSL(print) (JNIEnv *env) {
    printf("Hello world");
    return 0;
}
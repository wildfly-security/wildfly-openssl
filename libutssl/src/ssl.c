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

#define CHECK_INIT() if(ssl_initialized == 0) {throwIllegalStateException(env, "OpenSSL has not been initalized"); return 0;}


#ifdef WIN32
#define LLT(X) (X)
#else
#define LLT(X) ((long)(X))
#endif
#define P2J(P)          ((jlong)LLT(P))
#define J2P(P, T)       ((T)LLT((jlong)P))

static int ssl_initialized = 0;
static jclass byteArrayClass, stringClass;

/**
 * The cached SSL context class
 */
static jclass    ssl_context_class;
static jmethodID sni_java_callback;


/* Callback used when OpenSSL receives a client hello with a Server Name
 * Indication extension.
 */
int ssl_callback_ServerNameIndication(SSL *ssl, int *al, tcn_ssl_ctxt_t *c)
{
    /* TODO: Is it better to cache the JNIEnv* during the call to handshake? */

    /* Get the JNI environment for this callback */
    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *env;
    const char *servername;
    jstring hostname;
    jlong original_ssl_context, new_ssl_context;
    (*javavm)->AttachCurrentThread(javavm, (void **)&env, NULL);

    // Get the host name presented by the client
    servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    // Convert parameters ready for the method call
    hostname = (*env)->NewStringUTF(env, servername);
    original_ssl_context = P2J(c->ctx);

    // Make the call
    new_ssl_context = (*env)->CallStaticLongMethod(env,
                                                            ssl_context_class,
                                                            sni_java_callback,
                                                            original_ssl_context,
                                                            hostname);

    if (original_ssl_context != new_ssl_context) {
        SSL_set_SSL_CTX(ssl, J2P(new_ssl_context, SSL_CTX *));
    }

    return SSL_TLSEXT_ERR_OK;
}

UT_OPENSSL(jint, initialize) (JNIEnv *e) {
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
        return throwIllegalStateException(e, "Invalid OpenSSL Version");
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
    clazz = (*e)->FindClass(e, "[B");
    byteArrayClass = (jclass) (*e)->NewGlobalRef(e, clazz);

    /* Cache the String.class for performance reasons */
    sClazz = (*e)->FindClass(e, "java/lang/String");
    stringClass = (jclass) (*e)->NewGlobalRef(e, sClazz);

    return (jint)0;
}

/* Initialize server context */
UT_OPENSSL(jlong, makeSSLContext)(JNIEnv *e, jobject o, jlong pool,
                                            jint protocol, jint mode)
{
    tcn_ssl_ctxt_t *c = NULL;
    SSL_CTX *ctx = NULL;
    jclass clazz;

    if (protocol == SSL_PROTOCOL_NONE) {
        throwIllegalStateException(e, "No SSL protocols requested");
        goto init_failed;
    }

    if (protocol == SSL_PROTOCOL_TLSV1_2) {
#ifdef HAVE_TLSV1_2
        if (mode == SSL_MODE_CLIENT)
            ctx = SSL_CTX_new(TLSv1_2_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = SSL_CTX_new(TLSv1_2_server_method());
        else
            ctx = SSL_CTX_new(TLSv1_2_method());
#endif
    } else if (protocol == SSL_PROTOCOL_TLSV1_1) {
#ifdef HAVE_TLSV1_1
        if (mode == SSL_MODE_CLIENT)
            ctx = SSL_CTX_new(TLSv1_1_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = SSL_CTX_new(TLSv1_1_server_method());
        else
            ctx = SSL_CTX_new(TLSv1_1_method());
#endif
    } else if (protocol == SSL_PROTOCOL_TLSV1) {
        if (mode == SSL_MODE_CLIENT)
            ctx = SSL_CTX_new(TLSv1_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = SSL_CTX_new(TLSv1_server_method());
        else
            ctx = SSL_CTX_new(TLSv1_method());
    } else if (protocol == SSL_PROTOCOL_SSLV3) {
        if (mode == SSL_MODE_CLIENT)
            ctx = SSL_CTX_new(SSLv3_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = SSL_CTX_new(SSLv3_server_method());
        else
            ctx = SSL_CTX_new(SSLv3_method());
    } else if (protocol == SSL_PROTOCOL_SSLV2) {
        /* requested but not supported */
#ifndef HAVE_TLSV1_2
    } else if (protocol & SSL_PROTOCOL_TLSV1_2) {
        /* requested but not supported */
#endif
#ifndef HAVE_TLSV1_1
    } else if (protocol & SSL_PROTOCOL_TLSV1_1) {
        /* requested but not supported */
#endif
    } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (mode == SSL_MODE_CLIENT)
                ctx = SSL_CTX_new(SSLv23_client_method());
        else if (mode == SSL_MODE_SERVER)
                ctx = SSL_CTX_new(SSLv23_server_method());
        else
                ctx = SSL_CTX_new(SSLv23_method());
#else
        if (mode == SSL_MODE_CLIENT)
                ctx = SSL_CTX_new(TLS_client_method());
        else if (mode == SSL_MODE_SERVER)
                ctx = SSL_CTX_new(TLS_server_method());
        else
                ctx = SSL_CTX_new(TLS_method());
#endif
    }

    if (!ctx) {
        char err[256];
        ERR_error_string(ERR_get_error(), err);
        throwIllegalStateException(e, err);
        goto init_failed;
    }
    if ((c = malloc(sizeof(tcn_ssl_ctxt_t))) == NULL) {
        throwIllegalStateException(e, "malloc failed");
        goto init_failed;
    }

    c->protocol = protocol;
    c->mode     = mode;
    c->ctx      = ctx;
    c->bio_os   = BIO_new(BIO_s_file());
    if (c->bio_os != NULL)
        BIO_set_fp(c->bio_os, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    SSL_CTX_set_options(c->ctx, SSL_OP_ALL);
    /* always disable SSLv2, as per RFC 6176 */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if (!(protocol & SSL_PROTOCOL_SSLV3))
        SSL_CTX_set_options(c->ctx, SSL_OP_NO_SSLv3);
    if (!(protocol & SSL_PROTOCOL_TLSV1))
        SSL_CTX_set_options(c->ctx, SSL_OP_NO_TLSv1);
#ifdef HAVE_TLSV1_1
    if (!(protocol & SSL_PROTOCOL_TLSV1_1))
        SSL_CTX_set_options(c->ctx, SSL_OP_NO_TLSv1_1);
#endif
#ifdef HAVE_TLSV1_2
    if (!(protocol & SSL_PROTOCOL_TLSV1_2))
        SSL_CTX_set_options(c->ctx, SSL_OP_NO_TLSv1_2);
#endif
    /*
     * Configure additional context ingredients
     */
    SSL_CTX_set_options(c->ctx, SSL_OP_SINGLE_DH_USE);
#ifdef HAVE_ECC
    SSL_CTX_set_options(c->ctx, SSL_OP_SINGLE_ECDH_USE);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    /* Disable SSL compression to be safe */
    SSL_CTX_set_options(c->ctx, SSL_OP_NO_COMPRESSION);
#endif


    /** To get back the tomcat wrapper from CTX */
    SSL_CTX_set_app_data(c->ctx, (char *)c);

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    /*
     * Disallow a session from being resumed during a renegotiation,
     * so that an acceptable cipher suite can be negotiated.
     */
    SSL_CTX_set_options(c->ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
    /* Release idle buffers to the SSL_CTX free list */
    SSL_CTX_set_mode(c->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
    /* Default session context id and cache size */
    SSL_CTX_sess_set_cache_size(c->ctx, SSL_DEFAULT_CACHE_SIZE);
    /* Session cache is disabled by default */
    SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_OFF);
    /* Longer session timeout */
    SSL_CTX_set_timeout(c->ctx, 14400);

    EVP_Digest((const unsigned char *)SSL_DEFAULT_VHOST_NAME,
               (unsigned long)((sizeof SSL_DEFAULT_VHOST_NAME) - 1),
               &(c->context_id[0]), NULL, EVP_sha1(), NULL);

    /* Set default Certificate verification level
     * and depth for the Client Authentication
     */
    c->verify_depth  = 1;
    c->verify_mode   = SSL_CVERIFY_UNSET;
    c->shutdown_type = SSL_SHUTDOWN_TYPE_UNSET;

    /* Set default password callback */
    //TODO: fixme, do we need to support these callbacks?
    //SSL_CTX_set_default_passwd_cb(c->ctx, (pem_password_cb *)SSL_password_callback);
    //SSL_CTX_set_default_passwd_cb_userdata(c->ctx, (void *)(&tcn_password_callback));
    //SSL_CTX_set_info_callback(c->ctx, SSL_callback_handshake);

    /* Cache Java side SNI callback if not already cached */
    if (ssl_context_class == NULL) {
        ssl_context_class = (*e)->NewGlobalRef(e, o);
        sni_java_callback = (*e)->GetStaticMethodID(e, ssl_context_class,
                                                    "sniCallBack", "(JLjava/lang/String;)J");
    }

    /* Set up OpenSSL call back if SNI is provided by the client */
    SSL_CTX_set_tlsext_servername_callback(c->ctx, ssl_callback_ServerNameIndication);
    SSL_CTX_set_tlsext_servername_arg(c->ctx, c);

    /* Cache the byte[].class for performance reasons */
    clazz = (*e)->FindClass(e, "[B");
    byteArrayClass = (jclass) (*e)->NewGlobalRef(e, clazz);

    return P2J(c);
init_failed:
    return 0;
}

//
//static apr_status_t ssl_context_cleanup(void *data)
//{
//    tcn_ssl_ctxt_t *c = (tcn_ssl_ctxt_t *)data;
//    if (c) {
//        int i;
//        if (c->crl)
//            X509_STORE_free(c->crl);
//        c->crl = NULL;
//        if (c->ctx)
//            SSL_CTX_free(c->ctx);
//        c->ctx = NULL;
//        for (i = 0; i < SSL_AIDX_MAX; i++) {
//            if (c->certs[i]) {
//                X509_free(c->certs[i]);
//                c->certs[i] = NULL;
//            }
//            if (c->keys[i]) {
//                EVP_PKEY_free(c->keys[i]);
//                c->keys[i] = NULL;
//            }
//        }
//        if (c->bio_is) {
//            SSL_BIO_close(c->bio_is);
//            c->bio_is = NULL;
//        }
//        if (c->bio_os) {
//            SSL_BIO_close(c->bio_os);
//            c->bio_os = NULL;
//        }
//
//        if (c->verifier) {
//            JNIEnv *e;
//            tcn_get_java_env(&e);
//            (*e)->DeleteGlobalRef(e, c->verifier);
//            c->verifier = NULL;
//        }
//        c->verifier_method = NULL;
//
//        if (c->next_proto_data) {
//            free(c->next_proto_data);
//            c->next_proto_data = NULL;
//        }
//        c->next_proto_len = 0;
//
//        if (c->alpn_proto_data) {
//            free(c->alpn_proto_data);
//            c->alpn_proto_data = NULL;
//        }
//        c->alpn_proto_len = 0;
//    }
//    return APR_SUCCESS;
//}
//
//UT_OPENSSL(jint, free)(JN, jlong ctx)
//{
//    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
//    /* Run and destroy the cleanup callback */
//    return apr_pool_cleanup_run(c->pool, c, ssl_context_cleanup);
//}


#include "utssl.h"
/* openssl is deprecated on OSX
   this pragma directive is requires to build it
   otherwise -Wall -Werror fail the build
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#if defined(SSL_OP_NO_TLSv1_1)
#define HAVE_TLSV1_1
#endif

#if defined(SSL_OP_NO_TLSv1_2)
#define HAVE_TLSV1_2
#endif


static int ssl_initialized = 0;
static jclass byteArrayClass, stringClass;

/**
 * The cached SSL context class
 */
static jclass    ssl_context_class;
static jmethodID sni_java_callback;

/* indexes for customer SSL data */
static int SSL_app_data2_idx = -1;
static int SSL_app_data3_idx = -1;

/* Storage and initialization for DH parameters. */
static struct dhparam {
    BIGNUM *(*const prime)(BIGNUM *); /* function to generate... */
    DH *dh;                           /* ...this, used for keys.... */
    const unsigned int min;           /* ...of length >= this. */
} dhparams[] = {
    { get_rfc3526_prime_8192, NULL, 6145 },
    { get_rfc3526_prime_6144, NULL, 4097 },
    { get_rfc3526_prime_4096, NULL, 3073 },
    { get_rfc3526_prime_3072, NULL, 2049 },
    { get_rfc3526_prime_2048, NULL, 1025 },
    { get_rfc2409_prime_1024, NULL, 0 }
};

/* Hand out the same DH structure though once generated as we leak
 * memory otherwise and freeing the structure up after use would be
 * hard to track and in fact is not needed at all as it is safe to
 * use the same parameters over and over again security wise (in
 * contrast to the keys itself) and code safe as the returned structure
 * is duplicated by OpenSSL anyway. Hence no modification happens
 * to our copy. */
DH *SSL_get_dh_params(unsigned keylen)
{
    unsigned n;

    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++)
        if (keylen >= dhparams[n].min)
            return dhparams[n].dh;

    return NULL; /* impossible to reach. */
}

/*
 * Hand out standard DH parameters, based on the authentication strength
 */
DH *SSL_callback_tmp_DH(SSL *ssl, int export, int keylen)
{
    EVP_PKEY *pkey = SSL_get_privatekey(ssl);
    int type = pkey ? EVP_PKEY_type(pkey->type) : EVP_PKEY_NONE;

    /*
     * OpenSSL will call us with either keylen == 512 or keylen == 1024
     * (see the definition of SSL_EXPORT_PKEYLENGTH in ssl_locl.h).
     * Adjust the DH parameter length according to the size of the
     * RSA/DSA private key used for the current connection, and always
     * use at least 1024-bit parameters.
     * Note: This may cause interoperability issues with implementations
     * which limit their DH support to 1024 bit - e.g. Java 7 and earlier.
     * In this case, SSLCertificateFile can be used to specify fixed
     * 1024-bit DH parameters (with the effect that OpenSSL skips this
     * callback).
     */
    if ((type == EVP_PKEY_RSA) || (type == EVP_PKEY_DSA)) {
        keylen = EVP_PKEY_bits(pkey);
    }
    return SSL_get_dh_params(keylen);
}


void SSL_BIO_close(BIO *bi)
{
    if (bi == NULL)
        return;
    else
        BIO_free(bi);
}

void SSL_init_app_data2_3_idx(void)
{
    int i;

    if (SSL_app_data2_idx > -1) {
        return;
    }

    /* we _do_ need to call this twice */
    for (i = 0; i <= 1; i++) {
        SSL_app_data2_idx =
            SSL_get_ex_new_index(0,
                                 "Second Application Data for SSL",
                                 NULL, NULL, NULL);
    }

    if (SSL_app_data3_idx > -1) {
        return;
    }

    SSL_app_data3_idx =
            SSL_get_ex_new_index(0,
                                 "Third Application Data for SSL",
                                  NULL, NULL, NULL);
}
/*the the SSL context structure associated with the context*/
tcn_ssl_ctxt_t *SSL_get_app_data2(SSL *ssl)
{
    return (tcn_ssl_ctxt_t *)SSL_get_ex_data(ssl, SSL_app_data2_idx);
}

void SSL_set_app_data2(SSL *ssl, void *arg)
{
    SSL_set_ex_data(ssl, SSL_app_data2_idx, (char *)arg);
    return;
}


void *SSL_get_app_data3(const SSL *ssl)
{
    return SSL_get_ex_data(ssl, SSL_app_data3_idx);
}

void SSL_set_app_data3(SSL *ssl, void *arg)
{
    SSL_set_ex_data(ssl, SSL_app_data3_idx, arg);
}
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
    printf("OpenSSL version %lx \n", OPENSSL_VERSION_NUMBER);
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
    SSL_init_app_data2_3_idx();
    OpenSSL_add_all_algorithms();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_load_builtin_engines();
#endif
    OPENSSL_load_builtin_modules();

    ssl_thread_setup();

    //TODO: engine support?

    /* Cache the byte[].class for performance reasons */
    clazz = (*e)->FindClass(e, "[B");
    byteArrayClass = (jclass) (*e)->NewGlobalRef(e, clazz);

    /* Cache the String.class for performance reasons */
    sClazz = (*e)->FindClass(e, "java/lang/String");
    stringClass = (jclass) (*e)->NewGlobalRef(e, sClazz);

    alpn_init(e);
    session_init(e);

    return (jint)0;
}

/* Initialize server context */
UT_OPENSSL(jlong, makeSSLContext)(JNIEnv *e, jobject o,
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
#else
        throwIllegalStateException(e, "TLSV1_2 not supported");
        goto init_failed;
#endif
    } else if (protocol == SSL_PROTOCOL_TLSV1_1) {
#ifdef HAVE_TLSV1_1
        if (mode == SSL_MODE_CLIENT)
            ctx = SSL_CTX_new(TLSv1_1_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = SSL_CTX_new(TLSv1_1_server_method());
        else
            ctx = SSL_CTX_new(TLSv1_1_method());
#else
        throwIllegalStateException(e, "TLSV1_1 not supported");
        goto init_failed;
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
        throwIllegalStateException(e, "SSLV2 not supported");
        goto init_failed;
#ifndef HAVE_TLSV1_2
    } else if (protocol & SSL_PROTOCOL_TLSV1_2) {
        /* requested but not supported */
        throwIllegalStateException(e, "TLSV1_2 not supported");
        goto init_failed;
#endif
#ifndef HAVE_TLSV1_1
    } else if (protocol & SSL_PROTOCOL_TLSV1_1) {
        /* requested but not supported */
        throwIllegalStateException(e, "TLSV1_1 not supported");
        goto init_failed;
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
    memset(c, 0, sizeof(*c));

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
    setup_session_context(e, c);
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


UT_OPENSSL(jobjectArray, getCiphers)(JNIEnv *e, jobject o, jlong ssl)
{
    STACK_OF(SSL_CIPHER) *sk;
    int len;
    jobjectArray array;
    SSL_CIPHER *cipher;
    const char *name;
    int i;
    jstring c_name;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return NULL;
    }

    sk = SSL_get_ciphers(ssl_);
    len = sk_SSL_CIPHER_num(sk);

    if (len <= 0) {
        /* No peer certificate chain as no auth took place yet, or the auth was not successful. */
        return NULL;
    }

    /* Create the byte[][] array that holds all the certs */
    array = (*e)->NewObjectArray(e, len, stringClass, NULL);

    for (i = 0; i < len; i++) {
        cipher = (SSL_CIPHER*) sk_SSL_CIPHER_value(sk, i);
        name = SSL_CIPHER_get_name(cipher);

        c_name = (*e)->NewStringUTF(e, name);
        (*e)->SetObjectArrayElement(e, array, i, c_name);
    }
    return array;
}

UT_OPENSSL(jboolean, setCipherSuites)(JNIEnv *e, jobject o, jlong ssl,
                                                         jstring ciphers)
{
    jboolean rv = JNI_TRUE;
    SSL *ssl_ = J2P(ssl, SSL *);
    TCN_ALLOC_CSTRING(ciphers);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return JNI_FALSE;
    }

    UNREFERENCED(o);
    if (!J2S(ciphers)) {
        return JNI_FALSE;
    }
    if (!SSL_set_cipher_list(ssl_, J2S(ciphers))) {
        char err[256];
        ERR_error_string(ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
    }
    TCN_FREE_CSTRING(ciphers);
    return rv;
}

UT_OPENSSL(jint, freeSSLContext)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    UNREFERENCED_STDARGS;
    /* Run and destroy the cleanup callback */
    if (c) {
        int i;
        if (c->crl) {
            X509_STORE_free(c->crl);
        }
        c->crl = NULL;
        if (c->ctx) {
            SSL_CTX_free(c->ctx);
        }
        c->ctx = NULL;
        for (i = 0; i < SSL_AIDX_MAX; i++) {
            if (c->certs[i]) {
                X509_free(c->certs[i]);
                c->certs[i] = NULL;
            }
            if (c->keys[i]) {
                printf("b %d", i);
                EVP_PKEY_free(c->keys[i]);
                c->keys[i] = NULL;
            }
        }
        if (c->bio_is) {
            SSL_BIO_close(c->bio_is);
            c->bio_is = NULL;
        }
        if (c->bio_os) {
            SSL_BIO_close(c->bio_os);
            c->bio_os = NULL;
        }

        if (c->verifier) {
            JNIEnv *e;
            tcn_get_java_env(&e);
            (*e)->DeleteGlobalRef(e, c->verifier);
            c->verifier = NULL;
        }
        c->verifier_method = NULL;

        if (c->next_proto_data) {
            free(c->next_proto_data);
            c->next_proto_data = NULL;
        }
        c->next_proto_len = 0;

        if (c->alpn_proto_data) {
            free(c->alpn_proto_data);
            c->alpn_proto_data = NULL;
        }
        c->alpn_proto_len = 0;
    }
    return 0;
}

UT_OPENSSL(void, setSSLContextOptions)(JNIEnv *e, jobject o, jlong ctx,
                                                 jint opt)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED_STDARGS;
    TCN_ASSERT(ctx != 0);
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    /* Clear the flag if not supported */
    if (opt & 0x00040000)
        opt &= ~0x00040000;
#endif
    SSL_CTX_set_options(c->ctx, opt);
}

UT_OPENSSL(void, clearSSLContextOptions)(JNIEnv *e, jobject o, jlong ctx,
                                                   jint opt)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED_STDARGS;
    TCN_ASSERT(ctx != 0);
    SSL_CTX_clear_options(c->ctx, opt);
}

UT_OPENSSL(jboolean, setCipherSuite)(JNIEnv *e, jobject o, jlong ctx,
                                                         jstring ciphers)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    TCN_ALLOC_CSTRING(ciphers);
    jboolean rv = JNI_TRUE;
#ifndef HAVE_EXPORT_CIPHERS
    size_t len;
    char *buf;
#endif

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    if (!J2S(ciphers))
        return JNI_FALSE;

#ifndef HAVE_EXPORT_CIPHERS
    /*
     *  Always disable NULL and export ciphers,
     *  no matter what was given in the config.
     */
    len = strlen(J2S(ciphers)) + strlen(SSL_CIPHERS_ALWAYS_DISABLED) + 1;
    buf = malloc(len * sizeof(char *));
    if (buf == NULL)
        return JNI_FALSE;
    memcpy(buf, SSL_CIPHERS_ALWAYS_DISABLED, strlen(SSL_CIPHERS_ALWAYS_DISABLED));
    memcpy(buf + strlen(SSL_CIPHERS_ALWAYS_DISABLED), J2S(ciphers), strlen(J2S(ciphers)));
    buf[len - 1] = '\0';
    if (!SSL_CTX_set_cipher_list(c->ctx, buf)) {
#else
    if (!SSL_CTX_set_cipher_list(c->ctx, J2S(ciphers))) {
#endif
        char err[256];
        ERR_error_string(ERR_get_error(), err);
        tcn_Throw(e, "Unable to configure permitted SSL ciphers (%s)", err);
        rv = JNI_FALSE;
    }
#ifndef HAVE_EXPORT_CIPHERS
    free(buf);
#endif
    TCN_FREE_CSTRING(ciphers);
    return rv;
}

UT_OPENSSL(jboolean, setCARevocation)(JNIEnv *e, jobject o, jlong ctx,
                                                          jstring file,
                                                          jstring path)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    TCN_ALLOC_CSTRING(file);
    TCN_ALLOC_CSTRING(path);
    jboolean rv = JNI_FALSE;
    X509_LOOKUP *lookup;
    char err[256];

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    if (J2S(file) == NULL && J2S(path) == NULL)
        return JNI_FALSE;

    if (!c->crl) {
        if ((c->crl = X509_STORE_new()) == NULL)
            goto cleanup;
    }
    if (J2S(file)) {
        lookup = X509_STORE_add_lookup(c->crl, X509_LOOKUP_file());
        if (lookup == NULL) {
            ERR_error_string(ERR_get_error(), err);
            X509_STORE_free(c->crl);
            c->crl = NULL;
            tcn_Throw(e, "Lookup failed for file %s (%s)", J2S(file), err);
            goto cleanup;
        }
        X509_LOOKUP_load_file(lookup, J2S(file), X509_FILETYPE_PEM);
    }
    if (J2S(path)) {
        lookup = X509_STORE_add_lookup(c->crl, X509_LOOKUP_hash_dir());
        if (lookup == NULL) {
            ERR_error_string(ERR_get_error(), err);
            X509_STORE_free(c->crl);
            c->crl = NULL;
            tcn_Throw(e, "Lookup failed for path %s (%s)", J2S(file), err);
            goto cleanup;
        }
        X509_LOOKUP_add_dir(lookup, J2S(path), X509_FILETYPE_PEM);
    }
    rv = JNI_TRUE;
cleanup:
    TCN_FREE_CSTRING(file);
    TCN_FREE_CSTRING(path);
    return rv;
}

UT_OPENSSL(jboolean, setCACertificate)(JNIEnv *e, jobject o,
                                                           jlong ctx,
                                                           jstring file,
                                                           jstring path)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jboolean rv = JNI_TRUE;
    TCN_ALLOC_CSTRING(file);
    TCN_ALLOC_CSTRING(path);

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    if (file == NULL && path == NULL)
        return JNI_FALSE;

   /*
     * Configure Client Authentication details
     */
    if (!SSL_CTX_load_verify_locations(c->ctx,
                                       J2S(file), J2S(path))) {
        char err[256];
        ERR_error_string(ERR_get_error(), err);
        tcn_Throw(e, "Unable to configure locations "
                  "for client authentication (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    c->store = SSL_CTX_get_cert_store(c->ctx);
    if (c->mode) {
        STACK_OF(X509_NAME) *ca_certs;
        c->ca_certs++;
        ca_certs = SSL_CTX_get_client_CA_list(c->ctx);
        if (ca_certs == NULL) {
            SSL_load_client_CA_file(J2S(file));
            if (ca_certs != NULL)
                SSL_CTX_set_client_CA_list(c->ctx, ca_certs);
        }
        else {
            if (!SSL_add_file_cert_subjects_to_stack(ca_certs, J2S(file)))
                ca_certs = NULL;
        }
        if (ca_certs == NULL && c->verify_mode == SSL_CVERIFY_REQUIRE) {
            /*
             * Give a warning when no CAs were configured but client authentication
             * should take place. This cannot work.
             */
            if (c->bio_os) {
                BIO_printf(c->bio_os,
                            "[WARN] Oops, you want to request client "
                            "authentication, but no CAs are known for "
                            "verification!?");
            }
            else {
                fprintf(stderr,
                        "[WARN] Oops, you want to request client "
                        "authentication, but no CAs are known for "
                        "verification!?");
            }

        }
    }
cleanup:
    TCN_FREE_CSTRING(file);
    TCN_FREE_CSTRING(path);
    return rv;
}


UT_OPENSSL(jboolean, setCertificate)(JNIEnv *e, jobject o, jlong ctx,
                                                         jbyteArray javaCert, jbyteArray javaKey, jint idx)
{
    /* we get the key contents into a byte array */
    jbyte* bufferPtr = (*e)->GetByteArrayElements(e, javaKey, NULL);
    jsize lengthOfKey = (*e)->GetArrayLength(e, javaKey);
    unsigned char* key = malloc(lengthOfKey);
    memcpy(key, bufferPtr, lengthOfKey);
    (*e)->ReleaseByteArrayElements(e, javaKey, bufferPtr, 0);

    bufferPtr = (*e)->GetByteArrayElements(e, javaCert, NULL);
    jsize lengthOfCert = (*e)->GetArrayLength(e, javaCert);
    unsigned char* cert = malloc(lengthOfCert);
    memcpy(cert, bufferPtr, lengthOfCert);
    (*e)->ReleaseByteArrayElements(e, javaCert, bufferPtr, 0);

    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jboolean rv = JNI_TRUE;
    char err[256];

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    if (idx < 0 || idx >= SSL_AIDX_MAX) {
        throwIllegalStateException(e, "Invalid key type");
        rv = JNI_FALSE;
        goto cleanup;
    }
    const unsigned char *tmp = (const unsigned char *)cert;
    if ((c->certs[idx] = d2i_X509(NULL, &tmp, lengthOfCert)) == NULL) {
        ERR_error_string(ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    EVP_PKEY * evp = malloc(sizeof(EVP_PKEY));
    memset(evp, 0, sizeof(EVP_PKEY));
    if(c->keys[idx] != NULL) {
        free(c->keys[idx]);
    }
    c->keys[idx] = evp;

    BIO * bio = BIO_new(BIO_s_mem());
    BIO_write(bio, key, lengthOfKey);

    c->keys[idx] = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    BIO_free(bio);
    if (c->keys[idx] == NULL) {
        ERR_error_string(ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if (SSL_CTX_use_certificate(c->ctx, c->certs[idx]) <= 0) {
        ERR_error_string(ERR_get_error(), err);
        tcn_Throw(e, "Error setting certificate (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (SSL_CTX_use_PrivateKey(c->ctx, c->keys[idx]) <= 0) {
        ERR_error_string(ERR_get_error(), err);
        tcn_Throw(e, "Error setting private key (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (SSL_CTX_check_private_key(c->ctx) <= 0) {
        ERR_error_string(ERR_get_error(), err);
        tcn_Throw(e, "Private key does not match the certificate public key (%s)",
                  err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    //TODO: read DH and ECC params?

cleanup:
    free(key);
    free(cert);
    return rv;
}

/*
 * Adapted from Android:
 * https://android.googlesource.com/platform/external/openssl/+/master/patches/0003-jsse.patch
 */
const char* SSL_CIPHER_authentication_method(const SSL_CIPHER* cipher){
    switch (cipher->algorithm_mkey)
        {
    case SSL_kRSA:
        return SSL_TXT_RSA;
    case SSL_kDHr:
        return SSL_TXT_DH "_" SSL_TXT_RSA;
    case SSL_kDHd:
        return SSL_TXT_DH "_" SSL_TXT_DSS;
    case SSL_kEDH:
        switch (cipher->algorithm_auth)
            {
        case SSL_aDSS:
            return "DHE_" SSL_TXT_DSS;
        case SSL_aRSA:
            return "DHE_" SSL_TXT_RSA;
        case SSL_aNULL:
            return SSL_TXT_DH "_anon";
        default:
            return "UNKNOWN";
            }
    case SSL_kKRB5:
        return SSL_TXT_KRB5;
    case SSL_kECDHr:
        return SSL_TXT_ECDH "_" SSL_TXT_RSA;
    case SSL_kECDHe:
        return SSL_TXT_ECDH "_" SSL_TXT_ECDSA;
    case SSL_kEECDH:
        switch (cipher->algorithm_auth)
            {
        case SSL_aECDSA:
            return "ECDHE_" SSL_TXT_ECDSA;
        case SSL_aRSA:
            return "ECDHE_" SSL_TXT_RSA;
        case SSL_aNULL:
            return SSL_TXT_ECDH "_anon";
        default:
            return "UNKNOWN";
            }
    default:
        return "UNKNOWN";
    }
}

static const char* SSL_authentication_method(const SSL* ssl) {
{
    switch (ssl->version)
        {
        case SSL2_VERSION:
            return SSL_TXT_RSA;
        default:
            return SSL_CIPHER_authentication_method(ssl->s3->tmp.new_cipher);
        }
    }
}
/* Android end */

static int SSL_cert_verify(X509_STORE_CTX *ctx, void *arg) {
    /* Get Apache context back through OpenSSL context */
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    tcn_ssl_ctxt_t *c = SSL_get_app_data2(ssl);


    // Get a stack of all certs in the chain
    STACK_OF(X509) *sk = ctx->untrusted;

    int len = sk_X509_num(sk);
    unsigned i;
    X509 *cert;
    int length;
    unsigned char *buf;
    JNIEnv *e;
    jbyteArray array;
    jbyteArray bArray;
    const char *authMethod;
    jstring authMethodString;
    jboolean result;
    int r;
    tcn_get_java_env(&e);

    // Create the byte[][] array that holds all the certs
    array = (*e)->NewObjectArray(e, len, byteArrayClass, NULL);

    for(i = 0; i < len; i++) {
        cert = (X509*) sk_X509_value(sk, i);

        buf = NULL;
        length = i2d_X509(cert, &buf);
        if (length < 0) {
            // In case of error just return an empty byte[][]
            array = (*e)->NewObjectArray(e, 0, byteArrayClass, NULL);
            // We need to delete the local references so we not leak memory as this method is called via callback.
            OPENSSL_free(buf);
            break;
        }
        bArray = (*e)->NewByteArray(e, length);
        (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);
        (*e)->SetObjectArrayElement(e, array, i, bArray);

        // Delete the local reference as we not know how long the chain is and local references are otherwise
        // only freed once jni method returns.
        (*e)->DeleteLocalRef(e, bArray);
        OPENSSL_free(buf);
    }

    authMethod = SSL_authentication_method(ssl);
    authMethodString = (*e)->NewStringUTF(e, authMethod);

    result = (*e)->CallBooleanMethod(e, c->verifier, c->verifier_method, P2J(ssl), array,
            authMethodString);

    r = result == JNI_TRUE ? 1 : 0;

    // We need to delete the local references so we not leak memory as this method is called via callback.
    (*e)->DeleteLocalRef(e, authMethodString);
    (*e)->DeleteLocalRef(e, array);
    return r;
}


UT_OPENSSL(void, setCertVerifyCallback)(JNIEnv *e, jobject o, jlong ctx, jobject verifier)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    if (verifier == NULL) {
        SSL_CTX_set_cert_verify_callback(c->ctx, NULL, NULL);
    } else {
        jclass verifier_class = (*e)->GetObjectClass(e, verifier);
        jmethodID method = (*e)->GetMethodID(e, verifier_class, "verify", "(J[[BLjava/lang/String;)Z");

        if (method == NULL) {
            return;
        }
        // Delete the reference to the previous specified verifier if needed.
        if (c->verifier != NULL) {
            (*e)->DeleteLocalRef(e, c->verifier);
        }
        c->verifier = (*e)->NewGlobalRef(e, verifier);
        c->verifier_method = method;

        SSL_CTX_set_cert_verify_callback(c->ctx, SSL_cert_verify, NULL);
    }
}

UT_OPENSSL(jboolean, setSessionIdContext)(JNIEnv *e, jobject o, jlong ctx, jbyteArray sidCtx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int len = (*e)->GetArrayLength(e, sidCtx);
    unsigned char *buf;
    int res;

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    buf = malloc(len);

    (*e)->GetByteArrayRegion(e, sidCtx, 0, len, (jbyte*) buf);

    res = SSL_CTX_set_session_id_context(c->ctx, buf, len);
    free(buf);

    if (res == 1) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}


static void ssl_info_callback(const SSL *ssl, int where, int ret) {
    int *handshakeCount = NULL;
    if (0 != (where & SSL_CB_HANDSHAKE_START)) {
        handshakeCount = (int*) SSL_get_app_data3(ssl);
        if (handshakeCount != NULL) {
            ++(*handshakeCount);
        }
    }
}

UT_OPENSSL(jlong, newSSL)(JNIEnv *e, jobject o, jlong ctx /* tcn_ssl_ctxt_t * */,
                                                   jboolean server) {
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int *handshakeCount = malloc(sizeof(int));
    SSL *ssl;
    tcn_ssl_conn_t *con;

    UNREFERENCED_STDARGS;

    TCN_ASSERT(ctx != 0);
    ssl = SSL_new(c->ctx);
    if (ssl == NULL) {
        throwIllegalStateException(e, "cannot create new ssl");
        return 0;
    }
    if ((con = malloc(sizeof(tcn_ssl_conn_t))) == NULL) {
        throwIllegalStateException(e, "Failed to allocate memory");
        return 0;
    }
    memset(con, 0, sizeof(*con));
    con->ctx  = c;
    con->ssl  = ssl;
    con->shutdown_type = c->shutdown_type;

    /* Store the handshakeCount in the SSL instance. */
    *handshakeCount = 0;
    SSL_set_app_data3(ssl, handshakeCount);

    /* Add callback to keep track of handshakes. */
    SSL_CTX_set_info_callback(c->ctx, ssl_info_callback);

    if (server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }

    /* Setup verify and seed */
    SSL_set_verify_result(ssl, X509_V_OK);
    //TODO: do we need our seed? It seems the default seed should be more secure
    //SSL_rand_seed(c->rand_file);

    /* Store for later usage in SSL_callback_SSL_verify */
    SSL_set_app_data2(ssl, c);
    SSL_set_app_data(ssl, con);
    return P2J(ssl);
}


/* Free the SSL * and its associated internal BIO */
UT_OPENSSL(void, freeSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    int *handshakeCount = SSL_get_app_data3(ssl_);

    if (handshakeCount != NULL) {
        free(handshakeCount);
    }

    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)SSL_get_app_data(ssl_);
    if(con->alpn_selection_callback != NULL) {
        (*e)->DeleteGlobalRef(e, con->alpn_selection_callback);
    }
    free(con);
    SSL_free(ssl_);
}


UT_OPENSSL(jlong, bufferAddress)(JNIEnv *e, jobject o, jobject bb)
{
    UNREFERENCED(o);
    if(bb == NULL) {
        throwIllegalArgumentException(e, "Buffer was null");
    }
    return P2J((*e)->GetDirectBufferAddress(e, bb));
}


/* Make a BIO pair (network and internal) for the provided SSL * and return the network BIO */
UT_OPENSSL(jlong, makeNetworkBIO)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    BIO *internal_bio;
    BIO *network_bio;

    UNREFERENCED(o);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        goto fail;
    }

    if (BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0) != 1) {
        throwIllegalStateException(e, "BIO_new_bio_pair failed");
        goto fail;
    }

    SSL_set_bio(ssl_, internal_bio, internal_bio);

    return P2J(network_bio);
 fail:
    return 0;
}


UT_OPENSSL(jint, doHandshake)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return SSL_do_handshake(ssl_);
}

UT_OPENSSL(jint, renegotiate)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return SSL_renegotiate(ssl_);
}


UT_OPENSSL(jint, getLastErrorNumber)(JNIEnv *e, jobject o) {
    return ERR_get_error();
}



UT_OPENSSL(jint /* nbytes */, pendingWrittenBytesInBIO)(JNIEnv *e, jobject o,
                                                                     jlong bio /* BIO * */) {
    UNREFERENCED_STDARGS;

    return BIO_ctrl_pending(J2P(bio, BIO *));
}

/* How much is available for reading in the given SSL struct? */
UT_OPENSSL(jint, pendingReadableBytesInSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
    UNREFERENCED_STDARGS;

    return SSL_pending(J2P(ssl, SSL *));
}

/* Write wlen bytes from wbuf into bio */
UT_OPENSSL(jint /* status */, writeToBIO)(JNIEnv *e, jobject o,
                                                       jlong bio /* BIO * */,
                                                       jlong wbuf /* char* */,
                                                       jint wlen /* sizeof(wbuf) */) {
    UNREFERENCED_STDARGS;

    return BIO_write(J2P(bio, BIO *), J2P(wbuf, void *), wlen);

}

/* Read up to rlen bytes from bio into rbuf */
UT_OPENSSL(jint /* status */, readFromBIO)(JNIEnv *e, jobject o,
                                                        jlong bio /* BIO * */,
                                                        jlong rbuf /* char * */,
                                                        jint rlen /* sizeof(rbuf) - 1 */) {
    UNREFERENCED_STDARGS;

    return BIO_read(J2P(bio, BIO *), J2P(rbuf, void *), rlen);
}

/* Write up to wlen bytes of application data to the ssl BIO (encrypt) */
UT_OPENSSL(jint /* status */, writeToSSL)(JNIEnv *e, jobject o,
                                                       jlong ssl /* SSL * */,
                                                       jlong wbuf /* char * */,
                                                       jint wlen /* sizeof(wbuf) */) {
    UNREFERENCED_STDARGS;

    return SSL_write(J2P(ssl, SSL *), J2P(wbuf, void *), wlen);
}

/* Read up to rlen bytes of application data from the given SSL BIO (decrypt) */
UT_OPENSSL(jint /* status */, readFromSSL)(JNIEnv *e, jobject o,
                                                        jlong ssl /* SSL * */,
                                                        jlong rbuf /* char * */,
                                                        jint rlen /* sizeof(rbuf) - 1 */) {
    UNREFERENCED_STDARGS;

    return SSL_read(J2P(ssl, SSL *), J2P(rbuf, void *), rlen);
}

/* Get the shutdown status of the engine */
UT_OPENSSL(jint /* status */, getShutdown)(JNIEnv *e, jobject o,
                                                        jlong ssl /* SSL * */) {
    UNREFERENCED_STDARGS;

    return SSL_get_shutdown(J2P(ssl, SSL *));
}

UT_OPENSSL(jint, isInInit)(JNIEnv *e, jobject o,
                                        jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED(o);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    } else {
        return SSL_in_init(ssl_) || SSL_renegotiate_pending(ssl_);
    }
}

/* Free a BIO * (typically, the network BIO) */
UT_OPENSSL(void, freeBIO)(JNIEnv *e, jobject o,
                                       jlong bio /* BIO * */) {
    BIO *bio_;
    UNREFERENCED_STDARGS;

    bio_ = J2P(bio, BIO *);
    BIO_free(bio_);
}


UT_OPENSSL(jstring, getErrorString)(JNIEnv *e, jobject o, jlong number)
{
    char buf[256];
    UNREFERENCED(o);
    ERR_error_string(number, buf);
    return tcn_new_string(e, buf);
}

/* Read which cipher was negotiated for the given SSL *. */
UT_OPENSSL(jstring, getCipherForSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */)
{
    return AJP_TO_JSTRING(SSL_get_cipher(J2P(ssl, SSL*)));
}


/* Read which protocol was negotiated for the given SSL *. */
UT_OPENSSL(jstring, getVersion)(JNIEnv *e, jobject o, jlong ssl /* SSL * */)
{
    return AJP_TO_JSTRING(SSL_get_version(J2P(ssl, SSL*)));
}


UT_OPENSSL(jobjectArray, getPeerCertChain)(JNIEnv *e, jobject o,
                                                  jlong ssl /* SSL * */)
{
    STACK_OF(X509) *sk;
    int len;
    int i;
    X509 *cert;
    int length;
    unsigned char *buf;
    jobjectArray array;
    jbyteArray bArray;

    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    // Get a stack of all certs in the chain.
    sk = SSL_get_peer_cert_chain(ssl_);

    len = sk_X509_num(sk);
    if (len <= 0) {

        /* No peer certificate chain as no auth took place yet, or the auth was not successful. */
        return NULL;
    }
    /* Create the byte[][] array that holds all the certs */
    array = (*e)->NewObjectArray(e, len, byteArrayClass, NULL);

    for(i = 0; i < len; i++) {
        cert = (X509*) sk_X509_value(sk, i);

        buf = NULL;
        length = i2d_X509(cert, &buf);
        if (length < 0) {
            OPENSSL_free(buf);
            /* In case of error just return an empty byte[][] */
            return (*e)->NewObjectArray(e, 0, byteArrayClass, NULL);
        }
        bArray = (*e)->NewByteArray(e, length);
        (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);
        (*e)->SetObjectArrayElement(e, array, i, bArray);

        /*
         * Delete the local reference as we not know how long the chain is and local references are otherwise
         * only freed once jni method returns.
         */
        (*e)->DeleteLocalRef(e, bArray);

        OPENSSL_free(buf);
    }
    return array;
}


/* Send CLOSE_NOTIFY to peer */
UT_OPENSSL(jint , shutdownSSL)(JNIEnv *e, jobject o, jlong ssl) {
    return SSL_shutdown(J2P(ssl, SSL *));
}


UT_OPENSSL(jbyteArray, getPeerCertificate)(JNIEnv *e, jobject o,
                                                  jlong ssl /* SSL * */)
{
    X509 *cert;
    int length;
    unsigned char *buf = NULL;
    jbyteArray bArray;

    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    /* Get a stack of all certs in the chain */
    cert = SSL_get_peer_certificate(ssl_);
    if (cert == NULL) {
        return NULL;
    }

    length = i2d_X509(cert, &buf);

    bArray = (*e)->NewByteArray(e, length);
    (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);

    /*
     * We need to free the cert as the reference count is incremented by one and it is not destroyed when the
     * session is freed.
     * See https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html
     */
    X509_free(cert);

    OPENSSL_free(buf);

    return bArray;
}


UT_OPENSSL(jint, version)(JNIEnv *e)
{
    return OPENSSL_VERSION_NUMBER;
}


#include "wfssl.h"

#if defined(SSL_OP_NO_TLSv1_1)
#define HAVE_TLSV1_1
#endif

#if defined(SSL_OP_NO_TLSv1_2)
#define HAVE_TLSV1_2
#endif

#ifdef __APPLE__
#define LIBCRYPTO_NAME "libcrypto.dylib"
#define LIBSSL_NAME "libssl.dylib"
#else
#ifdef WIN32
#define LIBCRYPTO_NAME "libeay32.dll"
#define LIBSSL_NAME "ssleay32.dll"
#define FALLBACK_LIBSSL_NAME "libssl32.dll"
#else
#define LIBCRYPTO_NAME "libcrypto.so"
#define LIBSSL_NAME "libssl.so"
#endif
#endif

#define WF_OPENSSL_MIN_VERSION 0x010001000L /* minimum required version of OpenSSL to work with */

static int ssl_initialized = 0;
static jclass byteArrayClass, stringClass;

ssl_dynamic_methods ssl_methods;
crypto_dynamic_methods crypto_methods;

/**
 * The cached SSL context class
 */
static jclass    ssl_context_class;
static jmethodID sni_java_callback;

/* indexes for customer SSL data */
static int SSL_app_data1_idx = -1; /* connection metadata */
static int SSL_app_data2_idx = -1; /* context metadata */
static int SSL_app_data3_idx = -1; /* handshake count */
static int SSL_CTX_app_data1_idx = -1; /* context metadata */

WF_OPENSSL(jint, initialize) (JNIEnv *e, jobject o, jstring libCryptoPath, jstring libSSLPath);
WF_OPENSSL(jlong, makeSSLContext)(JNIEnv *e, jobject o, jint protocol, jint mode);
WF_OPENSSL(jobjectArray, getCiphers)(JNIEnv *e, jobject o, jlong ssl);
WF_OPENSSL(jboolean, setCipherSuites)(JNIEnv *e, jobject o, jlong ssl, jstring ciphers);
WF_OPENSSL(jboolean, setServerNameIndication)(JNIEnv *e, jobject o, jlong ssl, jstring ciphers);
WF_OPENSSL(jint, freeSSLContext)(JNIEnv *e, jobject o, jlong ctx);
WF_OPENSSL(void, setSSLContextOptions)(JNIEnv *e, jobject o, jlong ctx, jint opt);
WF_OPENSSL(void, clearSSLContextOptions)(JNIEnv *e, jobject o, jlong ctx, jint opt);
WF_OPENSSL(void, setSSLOptions)(JNIEnv *e, jobject o, jlong ssl, jint opt);
WF_OPENSSL(void, clearSSLOptions)(JNIEnv *e, jobject o, jlong ssl, jint opt);
WF_OPENSSL(jboolean, setCipherSuite)(JNIEnv *e, jobject o, jlong ctx, jstring ciphers);
WF_OPENSSL(jboolean, setCARevocation)(JNIEnv *e, jobject o, jlong ctx, jstring file, jstring path);
WF_OPENSSL(jboolean, setCertificate)(JNIEnv *e, jobject o, jlong ctx, jbyteArray javaCert, jobjectArray intermediateCerts, jbyteArray javaKey, jint idx);
WF_OPENSSL(void, setCertVerifyCallback)(JNIEnv *e, jobject o, jlong ctx, jobject verifier);
WF_OPENSSL(jboolean, setSessionIdContext)(JNIEnv *e, jobject o, jlong ctx, jbyteArray sidCtx);
WF_OPENSSL(jlong, newSSL)(JNIEnv *e, jobject o, jlong ctx /* tcn_ssl_ctxt_t * */, jboolean server);
WF_OPENSSL(void, freeSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jlong, bufferAddress)(JNIEnv *e, jobject o, jobject bb);
WF_OPENSSL(jlong, makeNetworkBIO)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jint, doHandshake)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(void, saveServerCipher)(JNIEnv *e, jobject o, jlong ssl /* SSL * */, jint server_cipher);
WF_OPENSSL(jint, getSSLError)(JNIEnv *e, jobject o, jlong ssl, jlong code);
WF_OPENSSL(jint, renegotiate)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jint, getLastErrorNumber)(JNIEnv *e, jobject o);
WF_OPENSSL(jint /* nbytes */, pendingWrittenBytesInBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */);
WF_OPENSSL(jint, pendingReadableBytesInSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jint /* status */, writeToBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */, jlong wbuf /* char* */, jint wlen /* sizeof(wbuf) */);
WF_OPENSSL(jint /* status */, readFromBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */, jlong rbuf /* char * */, jint rlen /* sizeof(rbuf) - 1 */);
WF_OPENSSL(jint /* status */, writeToSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */, jlong wbuf /* char * */, jint wlen /* sizeof(wbuf) */);
WF_OPENSSL(jint /* status */, readFromSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */, jlong rbuf /* char * */, jint rlen /* sizeof(rbuf) - 1 */);
WF_OPENSSL(jint /* status */, getShutdown)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jint, isInInit)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(void, freeBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */);
WF_OPENSSL(jstring, getErrorString)(JNIEnv *e, jobject o, jlong number);
WF_OPENSSL(jstring, getCipherForSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jstring, getVersion)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jobjectArray, getPeerCertChain)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jint , shutdownSSL)(JNIEnv *e, jobject o, jlong ssl);
WF_OPENSSL(jbyteArray, getPeerCertificate)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(jstring, version)(JNIEnv *e);
void init_app_data_idx(void);
void SSL_set_app_data1(SSL *ssl, tcn_ssl_conn_t *arg);
void SSL_set_app_data2(SSL *ssl, tcn_ssl_ctxt_t *arg);
void *SSL_get_app_data3(const SSL *ssl);
void SSL_set_app_data3(SSL *ssl, void *arg);
void SSL_CTX_set_app_data1(SSL_CTX *ssl, void *arg);
void SSL_BIO_close(BIO *bi);
int ssl_callback_ServerNameIndication(SSL *ssl, int *al, tcn_ssl_ctxt_t *c);
int load_openssl_dynamic_methods(JNIEnv *e, const char * libCryptoPath, const char * libSSLPath);
void setupDH(JNIEnv *e, SSL_CTX * ctx);

void init_app_data_idx(void)
{
    if (SSL_app_data1_idx > -1) {
        return;
    }

    if(ssl_methods.SSL_get_ex_new_index != NULL) {
        SSL_app_data1_idx = ssl_methods.SSL_get_ex_new_index(0, "First Application Data for SSL", NULL, NULL, NULL);
        SSL_app_data2_idx = ssl_methods.SSL_get_ex_new_index(0, "Second Application Data for SSL", NULL, NULL, NULL);
        SSL_app_data3_idx = ssl_methods.SSL_get_ex_new_index(0, "Third Application Data for SSL", NULL, NULL, NULL);
        SSL_CTX_app_data1_idx = ssl_methods.SSL_CTX_get_ex_new_index(0, "First Application Data for SSL_CTX", NULL, NULL, NULL);
    } else {
        SSL_app_data1_idx = crypto_methods.CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0, "First Application Data for SSL", NULL, NULL, NULL);
        SSL_app_data2_idx = crypto_methods.CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0, "Second Application Data for SSL", NULL, NULL, NULL);
        SSL_app_data3_idx = crypto_methods.CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0, "Third Application Data for SSL", NULL, NULL, NULL);
        SSL_CTX_app_data1_idx = crypto_methods.CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, 0, "First Application Data for SSL_CTX", NULL, NULL, NULL);
    }
}
/*the the SSL context structure associated with the context*/
tcn_ssl_conn_t *SSL_get_app_data1(const SSL *ssl)
{
    return (tcn_ssl_conn_t *)ssl_methods.SSL_get_ex_data(ssl, SSL_app_data1_idx);
}

void SSL_set_app_data1(SSL *ssl, tcn_ssl_conn_t *arg)
{
    ssl_methods.SSL_set_ex_data(ssl, SSL_app_data1_idx, (char *)arg);
}
/*the the SSL context structure associated with the context*/
tcn_ssl_ctxt_t *SSL_get_app_data2(const SSL *ssl)
{
    return (tcn_ssl_ctxt_t *)ssl_methods.SSL_get_ex_data(ssl, SSL_app_data2_idx);
}

void SSL_set_app_data2(SSL *ssl, tcn_ssl_ctxt_t *arg)
{
    ssl_methods.SSL_set_ex_data(ssl, SSL_app_data2_idx, (char *)arg);
}

void *SSL_get_app_data3(const SSL *ssl)
{
    return (void *)ssl_methods.SSL_get_ex_data(ssl, SSL_app_data3_idx);
}

void SSL_set_app_data3(SSL *ssl, void *arg)
{
    ssl_methods.SSL_set_ex_data(ssl, SSL_app_data3_idx, (char *)arg);
}

tcn_ssl_ctxt_t *SSL_CTX_get_app_data1(const SSL_CTX *ssl)
{
    return (tcn_ssl_ctxt_t *)ssl_methods.SSL_CTX_get_ex_data(ssl, SSL_CTX_app_data1_idx);
}

void SSL_CTX_set_app_data1(SSL_CTX *ssl, void *arg)
{
    ssl_methods.SSL_CTX_set_ex_data(ssl, SSL_CTX_app_data1_idx, (char *)arg);
}

void SSL_BIO_close(BIO *bi)
{
    if (bi == NULL)
        return;
    else
        crypto_methods.BIO_free(bi);
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

    /*  Get the host name presented by the client */
    servername = ssl_methods.SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    /*  Convert parameters ready for the method call */
    hostname = (*env)->NewStringUTF(env, servername);
    original_ssl_context = P2J(c->ctx);

    /*  Make the call */
    new_ssl_context = (*env)->CallStaticLongMethod(env,
                                                            ssl_context_class,
                                                            sni_java_callback,
                                                            original_ssl_context,
                                                            hostname);

    if (original_ssl_context != new_ssl_context) {
        ssl_methods.SSL_set_SSL_CTX(ssl, J2P(new_ssl_context, SSL_CTX *));
    }

    return SSL_TLSEXT_ERR_OK;
}

#ifdef WIN32

#define REQUIRE_SYMBOL(handle, symb, target) target = (void*)GetProcAddress(handle, #symb); if(target == 0) { throwIllegalStateException(e, "Could not load required symbol from" #handle " " #symb); return 1;}
#define GET_SYMBOL(handle, symb, target) target = (void*)GetProcAddress(handle, #symb);

#define REQUIRE_SSL_SYMBOL_ALIAS(symb, alias) ssl_methods.alias = (void*)GetProcAddress(ssl, #symb); if(ssl_methods.alias == 0) { throwIllegalStateException(e, "Could not load required symbol from libssl: " #symb); return 1;}
#define GET_SSL_SYMBOL(symb) ssl_methods.symb = (void*)GetProcAddress(ssl, #symb);
#define REQUIRE_CRYPTO_SYMBOL_ALIAS(symb, alias) crypto_methods.alias = (void*)GetProcAddress(crypto, #symb); if(crypto_methods.alias == 0) { throwIllegalStateException(e, "Could not load required symbol from libcrypto: " #symb); return 1;}
#define GET_CRYPTO_SYMBOL(symb)  crypto_methods.symb = (void*)GetProcAddress(crypto, #symb);

#else

#define REQUIRE_SSL_SYMBOL_ALIAS(symb, alias) ssl_methods.alias = dlsym(ssl, #symb); if(ssl_methods.alias == 0) {throwIllegalStateException(e, "Could not load required symbol from libssl: " #symb); return 1;}
#define GET_SSL_SYMBOL(symb) ssl_methods.symb = dlsym(ssl, #symb);
#define REQUIRE_CRYPTO_SYMBOL_ALIAS(symb, alias) crypto_methods.alias = dlsym(crypto, #symb); if(crypto_methods.alias == 0) {throwIllegalStateException(e, "Could not load required symbol from libcrypto: " #symb); return 1;}
#define GET_CRYPTO_SYMBOL(symb) crypto_methods.symb = dlsym(crypto, #symb);
#endif

#define REQUIRE_SSL_SYMBOL(symb) REQUIRE_SSL_SYMBOL_ALIAS(symb, symb);
#define REQUIRE_CRYPTO_SYMBOL(symb) REQUIRE_CRYPTO_SYMBOL_ALIAS(symb, symb);

int load_openssl_dynamic_methods(JNIEnv *e, const char * libCryptoPath, const char * libSSLPath) {

#ifdef WIN32
	HMODULE crypto, ssl;

    if(libCryptoPath == NULL) {
	    crypto = LoadLibrary(LIBCRYPTO_NAME);
	} else {
        crypto = LoadLibrary(libCryptoPath);
	}
    if( crypto == NULL ) {
        throwIllegalStateException(e, "Could not load libeay32.dll");
        return 1;
    }
    GET_SYMBOL(crypto, SSLeay, ssl_methods.SSLeay);
    GET_SYMBOL(crypto, SSLeay_version, ssl_methods.SSLeay_version);
    if(ssl_methods.SSLeay == NULL) {
        REQUIRE_SYMBOL(crypto, OpenSSL_version_num, ssl_methods.SSLeay);
        REQUIRE_SYMBOL(crypto, OpenSSL_version, ssl_methods.SSLeay_version);
    }
    if(libSSLPath == NULL) {
	    ssl = LoadLibrary(LIBSSL_NAME);
        if(ssl == NULL) {
            ssl = LoadLibrary(FALLBACK_LIBSSL_NAME);
        }
	} else {
        ssl = LoadLibrary(libSSLPath);
    }
    if( ssl == NULL ) {
        throwIllegalStateException(e, "Could not load ssleay32.dll or libssl32.dll");
        return 1;
    }
#else
    void *ssl, *crypto;

    if(libCryptoPath == NULL) {
        crypto = dlopen(LIBCRYPTO_NAME, RTLD_LAZY);
    } else {
        crypto = dlopen(libCryptoPath, RTLD_LAZY);
    }

    if(libSSLPath == NULL) {
        ssl = dlopen(LIBSSL_NAME, RTLD_LAZY);
    } else {
        ssl = dlopen(libSSLPath, RTLD_LAZY);
    }

    if( ssl == NULL ) {
        printf("%s", dlerror());
        throwIllegalStateException(e, "Could not load libssl");
        return 1;
    }
    if( crypto == NULL ) {
        throwIllegalStateException(e, "Could not load libcrypto");
        return 1;
    }
    GET_SSL_SYMBOL(SSLeay);
    GET_SSL_SYMBOL(SSLeay_version);
    if(ssl_methods.SSLeay == NULL) {
        REQUIRE_SSL_SYMBOL_ALIAS(OpenSSL_version_num, SSLeay);
        REQUIRE_SSL_SYMBOL_ALIAS(OpenSSL_version, SSLeay_version);
    }
#endif

    if (ssl_methods.SSLeay() < WF_OPENSSL_MIN_VERSION) {
        ssl_initialized = 0;
        throwIllegalStateException(e, "Invalid OpenSSL Version (required OpenSSL 1.0.1 or newer)");
        return 1;
    }

    GET_SSL_SYMBOL(SSL_CTX_get_ex_new_index);
    REQUIRE_SSL_SYMBOL(SSL_get_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_set_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_get_ex_data_X509_STORE_CTX_idx);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_ex_data);
    if(ssl_methods.SSL_CTX_get_ex_new_index != NULL) {
        REQUIRE_SSL_SYMBOL(SSL_get_ex_new_index);
    } else {
        REQUIRE_CRYPTO_SYMBOL(CRYPTO_get_ex_new_index)
    }

    REQUIRE_SSL_SYMBOL(SSL_CIPHER_get_name);
    REQUIRE_SSL_SYMBOL(SSL_CTX_callback_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CTX_check_private_key);
    REQUIRE_SSL_SYMBOL(SSL_CTX_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CTX_free);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_cert_store);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_client_CA_list);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_timeout);
    REQUIRE_SSL_SYMBOL(SSL_CTX_load_verify_locations);
    REQUIRE_SSL_SYMBOL(SSL_CTX_new);
    REQUIRE_SSL_SYMBOL(SSL_CTX_sess_set_new_cb);
    REQUIRE_SSL_SYMBOL(SSL_CTX_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CIPHER_get_name);
    REQUIRE_SSL_SYMBOL(SSL_CTX_callback_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CTX_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CTX_sess_set_remove_cb);
    REQUIRE_SSL_SYMBOL(SSL_get_error);
    GET_SSL_SYMBOL(SSL_set_alpn_protos);
    GET_SSL_SYMBOL(SSL_CTX_set_alpn_select_cb);
    GET_SSL_SYMBOL(SSL_get0_alpn_selected);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_cert_verify_callback);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_cipher_list);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_default_verify_paths);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_session_id_context);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_timeout);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_verify);
    REQUIRE_SSL_SYMBOL(SSL_CTX_use_PrivateKey);
    REQUIRE_SSL_SYMBOL(SSL_CTX_use_certificate);
    REQUIRE_SSL_SYMBOL(SSL_SESSION_free);
    REQUIRE_SSL_SYMBOL(SSL_SESSION_get_id);
    REQUIRE_SSL_SYMBOL(SSL_SESSION_get_time);
    REQUIRE_SSL_SYMBOL(SSL_add_file_cert_subjects_to_stack);
    REQUIRE_SSL_SYMBOL(SSL_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_do_handshake);
    REQUIRE_SSL_SYMBOL(SSL_free);
    REQUIRE_SSL_SYMBOL(SSL_get_ciphers);
    REQUIRE_SSL_SYMBOL(SSL_get_current_cipher);
    REQUIRE_SSL_SYMBOL(SSL_get_peer_cert_chain);
    REQUIRE_SSL_SYMBOL(SSL_get_peer_certificate);
    REQUIRE_SSL_SYMBOL(SSL_get_privatekey);
    REQUIRE_SSL_SYMBOL(SSL_get_servername);
    REQUIRE_SSL_SYMBOL(SSL_get_session);
    REQUIRE_SSL_SYMBOL(SSL_get1_session);
    REQUIRE_SSL_SYMBOL(SSL_set_session);
    REQUIRE_SSL_SYMBOL(SSL_get_shutdown);
    REQUIRE_SSL_SYMBOL(SSL_get_version);

    GET_SSL_SYMBOL(SSL_library_init);
    if(ssl_methods.SSL_library_init == NULL) {
        REQUIRE_SSL_SYMBOL(OPENSSL_init_ssl);
    } else {
        REQUIRE_SSL_SYMBOL(SSL_load_error_strings);
    }

    REQUIRE_SSL_SYMBOL(SSL_load_client_CA_file);
    REQUIRE_SSL_SYMBOL(SSL_new);
    REQUIRE_SSL_SYMBOL(SSL_pending);
    REQUIRE_SSL_SYMBOL(SSL_set_read_ahead);
    REQUIRE_SSL_SYMBOL(SSL_read);
    REQUIRE_SSL_SYMBOL(SSL_renegotiate);
    REQUIRE_SSL_SYMBOL(SSL_renegotiate_pending);
    REQUIRE_SSL_SYMBOL(SSL_set_SSL_CTX);
    REQUIRE_SSL_SYMBOL(SSL_set_accept_state);
    REQUIRE_SSL_SYMBOL(SSL_set_bio);
    REQUIRE_SSL_SYMBOL(SSL_set_cipher_list);
    REQUIRE_SSL_SYMBOL(SSL_set_connect_state);
    REQUIRE_SSL_SYMBOL(SSL_set_verify);
    REQUIRE_SSL_SYMBOL(SSL_set_verify_result);
    REQUIRE_SSL_SYMBOL(SSL_shutdown);
    REQUIRE_SSL_SYMBOL(SSL_set_info_callback);
    REQUIRE_SSL_SYMBOL(SSL_write);
    GET_SSL_SYMBOL(TLSv1_1_server_method);
    GET_SSL_SYMBOL(TLSv1_2_server_method);
    GET_SSL_SYMBOL(SSLv23_client_method);
    GET_SSL_SYMBOL(SSLv23_method);
    GET_SSL_SYMBOL(SSLv23_server_method);
    GET_SSL_SYMBOL(TLS_client_method);
    GET_SSL_SYMBOL(TLS_server_method);
    GET_SSL_SYMBOL(TLS_method);

    REQUIRE_CRYPTO_SYMBOL(ASN1_INTEGER_cmp);
    REQUIRE_CRYPTO_SYMBOL(BIO_ctrl);
    REQUIRE_CRYPTO_SYMBOL(BIO_ctrl_pending);
    REQUIRE_CRYPTO_SYMBOL(BIO_free);
    REQUIRE_CRYPTO_SYMBOL(BIO_new);
    REQUIRE_CRYPTO_SYMBOL(BIO_new_bio_pair);
    REQUIRE_CRYPTO_SYMBOL(BIO_printf);
    REQUIRE_CRYPTO_SYMBOL(BIO_read);
    REQUIRE_CRYPTO_SYMBOL(BIO_s_file);
    REQUIRE_CRYPTO_SYMBOL(BIO_s_mem);
    REQUIRE_CRYPTO_SYMBOL(BIO_write);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_free);
    GET_CRYPTO_SYMBOL(CRYPTO_num_locks);
    GET_CRYPTO_SYMBOL(CRYPTO_set_dynlock_create_callback);
    GET_CRYPTO_SYMBOL(CRYPTO_set_dynlock_destroy_callback);
    GET_CRYPTO_SYMBOL(CRYPTO_set_dynlock_lock_callback);
    GET_CRYPTO_SYMBOL(CRYPTO_set_id_callback);
    GET_CRYPTO_SYMBOL(CRYPTO_set_locking_callback);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_set_mem_functions);
    REQUIRE_CRYPTO_SYMBOL(ERR_error_string);
    REQUIRE_CRYPTO_SYMBOL(ERR_get_error);
    GET_CRYPTO_SYMBOL(ERR_load_crypto_strings);
    GET_CRYPTO_SYMBOL(OPENSSL_add_all_algorithms_noconf);
    REQUIRE_CRYPTO_SYMBOL(EVP_Digest);
    REQUIRE_CRYPTO_SYMBOL(EVP_PKEY_bits);
    REQUIRE_CRYPTO_SYMBOL(EVP_PKEY_free);
    REQUIRE_CRYPTO_SYMBOL(EVP_PKEY_type);
    REQUIRE_CRYPTO_SYMBOL(EVP_sha1);
    REQUIRE_CRYPTO_SYMBOL(OPENSSL_load_builtin_modules);
    REQUIRE_CRYPTO_SYMBOL(PEM_read_bio_PrivateKey);
    REQUIRE_CRYPTO_SYMBOL(X509_CRL_verify);
    REQUIRE_CRYPTO_SYMBOL(X509_LOOKUP_ctrl);
    REQUIRE_CRYPTO_SYMBOL(X509_LOOKUP_file);
    REQUIRE_CRYPTO_SYMBOL(X509_LOOKUP_hash_dir);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_cleanup);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_current_cert);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_error);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_error_depth);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_ex_data);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_init);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_set_error);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_new);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_free);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_add_lookup);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_free);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_new);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_set_flags);
    REQUIRE_CRYPTO_SYMBOL(X509_cmp_current_time);
    REQUIRE_CRYPTO_SYMBOL(X509_free);
    REQUIRE_CRYPTO_SYMBOL(X509_get_issuer_name);
    REQUIRE_CRYPTO_SYMBOL(X509_get_pubkey);
    REQUIRE_CRYPTO_SYMBOL(X509_get_serialNumber);
    REQUIRE_CRYPTO_SYMBOL(X509_get_subject_name);
    REQUIRE_CRYPTO_SYMBOL(d2i_X509);
    REQUIRE_CRYPTO_SYMBOL(i2d_X509);
    GET_CRYPTO_SYMBOL(sk_num);
    if(crypto_methods.sk_num == NULL) {
        REQUIRE_CRYPTO_SYMBOL_ALIAS(OPENSSL_sk_num, sk_num)
    }
    GET_CRYPTO_SYMBOL(sk_value);
    if(crypto_methods.sk_value == NULL) {
        REQUIRE_CRYPTO_SYMBOL_ALIAS(OPENSSL_sk_value, sk_value)
    }

    REQUIRE_CRYPTO_SYMBOL(X509_free);
    GET_CRYPTO_SYMBOL(ENGINE_load_builtin_engines);
    GET_CRYPTO_SYMBOL(X509_STORE_CTX_get0_untrusted);
    REQUIRE_CRYPTO_SYMBOL(DH_free);
    REQUIRE_CRYPTO_SYMBOL(PEM_read_bio_DHparams);

    return 0;
}


WF_OPENSSL(jint, initialize) (JNIEnv *e, jobject o, jstring libCryptoPath, jstring libSSLPath) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    jclass clazz;
    jclass sClazz;
    const char * cPath = NULL;
    const char * sPath = NULL;
    TCN_ALLOC_CSTRING(libCryptoPath);
    TCN_ALLOC_CSTRING(libSSLPath);
    if(libCryptoPath != NULL) {
        cPath = J2S(libCryptoPath);
    }
    if(libSSLPath != NULL) {
        sPath = J2S(libSSLPath);
    }
    if(load_openssl_dynamic_methods(e, cPath, sPath) != 0) {
        TCN_FREE_CSTRING(libCryptoPath);
        TCN_FREE_CSTRING(libSSLPath);
        return 0;
    }
    TCN_FREE_CSTRING(libCryptoPath);
    TCN_FREE_CSTRING(libSSLPath);

    /* Check if already initialized */
    if (ssl_initialized++) {
        return 0;
    }
    /* We must register the library in full, to ensure our configuration
     * code can successfully test the SSL environment.
     */
    crypto_methods.CRYPTO_set_mem_functions(malloc, realloc, free);
    if(ssl_methods.SSL_library_init != NULL) {
        /*OpenSSL 1.0.x */
        ssl_methods.SSL_load_error_strings();
        crypto_methods.ERR_load_crypto_strings();
        ssl_methods.SSL_library_init();
        crypto_methods.OPENSSL_add_all_algorithms_noconf();
    } else {
        ssl_methods.OPENSSL_init_ssl(0, NULL);
    }
    init_app_data_idx();
    if(crypto_methods.ENGINE_load_builtin_engines != NULL) {
        crypto_methods.ENGINE_load_builtin_engines();
    }
    crypto_methods.OPENSSL_load_builtin_modules();

    ssl_thread_setup();

    /* TODO: engine support? */

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
WF_OPENSSL(jlong, makeSSLContext)(JNIEnv *e, jobject o, jint protocol, jint mode)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = NULL;
    SSL_CTX *ctx = NULL;
    jclass clazz;

    if (protocol == SSL_PROTOCOL_NONE) {
        throwIllegalStateException(e, "No SSL protocols requested");
        goto init_failed;
    }
    if (ssl_methods.TLS_server_method != NULL) {
        if (mode == SSL_MODE_CLIENT)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLS_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLS_server_method());
        else
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLS_method());
    } else {
        if (mode == SSL_MODE_CLIENT)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv23_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv23_server_method());
        else
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv23_method());
    }
    if (!ctx) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
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
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_ALL),NULL);
    /* always disable SSLv2, as per RFC 6176 */
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_NO_SSLv2),NULL);
    if (!(protocol & SSL_PROTOCOL_SSLV3))
        ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_NO_SSLv3),NULL);
    if (!(protocol & SSL_PROTOCOL_TLSV1))
        ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_NO_TLSv1),NULL);
    if(ssl_methods.TLSv1_1_server_method != NULL) { /* we use the presence of the method to test if it is supported */
        if (!(protocol & SSL_PROTOCOL_TLSV1_1))
            ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_NO_TLSv1_1),NULL);
    }
    if(ssl_methods.TLSv1_2_server_method != NULL) {
        if (!(protocol & SSL_PROTOCOL_TLSV1_2))
            ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_NO_TLSv1_2),NULL);
    }

    /* We need to disable TLSv1.3 if running on OpenSSL 1.1.0+ */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* This is equivalent to this macro:
        # define SSL_set_max_proto_version(s, version) \
                SSL_ctrl(s, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
        Reference: https://www.openssl.org/docs/manmaster/man3/SSL_set_max_proto_version.html
    */
    ssl_methods.SSL_CTX_ctrl((c->ctx), SSL_CTRL_SET_MAX_PROTO_VERSION, (TLS1_2_VERSION), NULL);
#endif

    /*
     * Configure additional context ingredients
     */
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_SINGLE_DH_USE),NULL);
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_SINGLE_ECDH_USE),NULL);
/* TODO: what do we do with these defines? */
#ifdef SSL_OP_NO_COMPRESSION
    /* Disable SSL compression to be safe */
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_NO_COMPRESSION),NULL);
#endif


    /** To get back the tomcat wrapper from CTX */
    SSL_CTX_set_app_data1(ctx, c);

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    /*
     * Disallow a session from being resumed during a renegotiation,
     * so that an acceptable cipher suite can be negotiated.
     */
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION),NULL);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
    /* Release idle buffers to the SSL_CTX free list */
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_MODE,(SSL_MODE_RELEASE_BUFFERS),NULL);
#endif
    setup_session_context(e, c);
    crypto_methods.EVP_Digest((const unsigned char *)SSL_DEFAULT_VHOST_NAME,
               (unsigned long)((sizeof SSL_DEFAULT_VHOST_NAME) - 1),
               &(c->context_id[0]), NULL, crypto_methods.EVP_sha1(), NULL);

    /* Set default Certificate verification level
     * and depth for the Client Authentication
     */
    c->verify_depth  = 1;
    c->verify_mode   = SSL_CVERIFY_UNSET;
    c->shutdown_type = SSL_SHUTDOWN_TYPE_UNSET;

    /* Cache Java side SNI callback if not already cached */
    if (ssl_context_class == NULL) {
        ssl_context_class = (*e)->NewGlobalRef(e, o);
        sni_java_callback = (*e)->GetStaticMethodID(e, ssl_context_class,
                                                    "sniCallBack", "(JLjava/lang/String;)J");
    }

    ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_ECDH_AUTO,1,NULL);

    /* Set up OpenSSL call back if SNI is provided by the client */
    ssl_methods.SSL_CTX_callback_ctrl(c->ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,(void (*)(void))ssl_callback_ServerNameIndication);
    ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG,0, (void *)c);

    /* Cache the byte[].class for performance reasons */
    clazz = (*e)->FindClass(e, "[B");
    byteArrayClass = (jclass) (*e)->NewGlobalRef(e, clazz);

    setupDH(e, ctx);
    return P2J(c);
init_failed:
    return 0;
}


WF_OPENSSL(jobjectArray, getCiphers)(JNIEnv *e, jobject o, jlong ssl)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    STACK_OF_SSL_CIPHER *sk;
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

    sk = ssl_methods.SSL_get_ciphers(ssl_);

    len = crypto_methods.sk_num(sk);

    if (len <= 0) {
        /* No peer certificate chain as no auth took place yet, or the auth was not successful. */
        return NULL;
    }

    /* Create the byte[][] array that holds all the certs */
    array = (*e)->NewObjectArray(e, len, stringClass, NULL);

    for (i = 0; i < len; i++) {
        cipher = (SSL_CIPHER*) crypto_methods.sk_value(sk, i);
        name = ssl_methods.SSL_CIPHER_get_name(cipher);

        c_name = (*e)->NewStringUTF(e, name);
        (*e)->SetObjectArrayElement(e, array, i, c_name);
    }
    return array;
}

WF_OPENSSL(jboolean, setCipherSuites)(JNIEnv *e, jobject o, jlong ssl, jstring ciphers)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
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
    if (!ssl_methods.SSL_set_cipher_list(ssl_, J2S(ciphers))) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
    }
    TCN_FREE_CSTRING(ciphers);
    return rv;
}

WF_OPENSSL(jint, freeSSLContext)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    UNREFERENCED_STDARGS;
    /* Run and destroy the cleanup callback */
    if (c) {
        int i;
        if (c->crl) {
            crypto_methods.X509_STORE_free(c->crl);
        }
        c->crl = NULL;
        if (c->ctx) {
            ssl_methods.SSL_CTX_free(c->ctx);
        }
        c->ctx = NULL;
        for (i = 0; i < SSL_AIDX_MAX; i++) {
            if (c->certs[i]) {
                crypto_methods.X509_free(c->certs[i]);
                c->certs[i] = NULL;
            }
            if (c->keys[i]) {
                crypto_methods.EVP_PKEY_free(c->keys[i]);
                c->keys[i] = NULL;
            }
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
    }
    return 0;
}

WF_OPENSSL(void, setSSLContextOptions)(JNIEnv *e, jobject o, jlong ctx, jint opt)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED_STDARGS;
    TCN_ASSERT(ctx != 0);
    /* Clear the flag if not supported */
    if (opt & 0x00040000) {
        opt &= ~0x00040000;
    }
	ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_OPTIONS,(opt),NULL);
}

WF_OPENSSL(void, clearSSLContextOptions)(JNIEnv *e, jobject o, jlong ctx, jint opt)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED_STDARGS;
    TCN_ASSERT(ctx != 0);
    ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_CLEAR_OPTIONS,(opt),NULL);
}

WF_OPENSSL(void, setSSLOptions)(JNIEnv *e, jobject o, jlong ssl, jint opt)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *c = J2P(ssl, SSL *);

    UNREFERENCED_STDARGS;
    /* Clear the flag if not supported */
    if (opt & 0x00040000)
        opt &= ~0x00040000;
    ssl_methods.SSL_ctrl(c,SSL_CTRL_OPTIONS,(opt),NULL);
}

WF_OPENSSL(void, clearSSLOptions)(JNIEnv *e, jobject o, jlong ssl, jint opt)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *c = J2P(ssl, SSL *);

    UNREFERENCED_STDARGS;
    ssl_methods.SSL_ctrl(c,SSL_CTRL_CLEAR_OPTIONS,(opt),NULL);
}

WF_OPENSSL(jboolean, setCipherSuite)(JNIEnv *e, jobject o, jlong ctx, jstring ciphers)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
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
    memmove(buf, SSL_CIPHERS_ALWAYS_DISABLED, strlen(SSL_CIPHERS_ALWAYS_DISABLED));
    memmove(buf + strlen(SSL_CIPHERS_ALWAYS_DISABLED), J2S(ciphers), strlen(J2S(ciphers)));
    buf[len - 1] = '\0';
    if (!ssl_methods.SSL_CTX_set_cipher_list(c->ctx, buf)) {
#else
    if (!ssl_methods.SSL_CTX_set_cipher_list(c->ctx, J2S(ciphers))) {
#endif
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Unable to configure permitted SSL ciphers (%s)", err);
        rv = JNI_FALSE;
    }
#ifndef HAVE_EXPORT_CIPHERS
    free(buf);
#endif
    TCN_FREE_CSTRING(ciphers);
    return rv;
}

WF_OPENSSL(jboolean, setServerNameIndication)(JNIEnv *e, jobject o, jlong ssl,
jstring hostName)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    jboolean rv = JNI_TRUE;
    SSL *ssl_ = J2P(ssl, SSL *);
    TCN_ALLOC_CSTRING(hostName);
    const char * hostNameString;
    hostNameString = J2S(hostName);
    if (ssl_ == NULL) {
        TCN_FREE_CSTRING(hostName);
        throwIllegalStateException(e, "ssl is null");
        return JNI_FALSE;
    }

    UNREFERENCED(o);
    if (hostNameString == NULL) {
        TCN_FREE_CSTRING(hostName);
        return JNI_FALSE;
    }
    if (ssl_methods.SSL_ctrl(ssl_, SSL_CTRL_SET_TLSEXT_HOSTNAME,
    TLSEXT_NAMETYPE_host_name, (void *)hostNameString)) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
    }
    TCN_FREE_CSTRING(hostName);
    return rv;
}

WF_OPENSSL(jboolean, setCARevocation)(JNIEnv *e, jobject o, jlong ctx, jstring file, jstring path)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
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
        if ((c->crl = crypto_methods.X509_STORE_new()) == NULL)
            goto cleanup;
    }
    if (J2S(file)) {
        lookup = crypto_methods.X509_STORE_add_lookup(c->crl, crypto_methods.X509_LOOKUP_file());
        if (lookup == NULL) {
            crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
            crypto_methods.X509_STORE_free(c->crl);
            c->crl = NULL;
            tcn_Throw(e, "Lookup failed for file %s (%s)", J2S(file), err);
            goto cleanup;
        }
        crypto_methods.X509_LOOKUP_ctrl((lookup),X509_L_FILE_LOAD,(J2S(file)),(long)(X509_FILETYPE_PEM),NULL);
    }
    if (J2S(path)) {
        lookup = crypto_methods.X509_STORE_add_lookup(c->crl, crypto_methods.X509_LOOKUP_hash_dir());
        if (lookup == NULL) {
            crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
            crypto_methods.X509_STORE_free(c->crl);
            c->crl = NULL;
            tcn_Throw(e, "Lookup failed for path %s (%s)", J2S(file), err);
            goto cleanup;
        }
        crypto_methods.X509_LOOKUP_ctrl((lookup),X509_L_ADD_DIR,(J2S(path)),(long)(X509_FILETYPE_PEM),NULL);
    }
    rv = JNI_TRUE;
cleanup:
    TCN_FREE_CSTRING(file);
    TCN_FREE_CSTRING(path);
    return rv;
}

WF_OPENSSL(jboolean, setCertificate)(JNIEnv *e, jobject o, jlong ctx, jbyteArray javaCert, jobjectArray intermediateCerts, jbyteArray javaKey, jint idx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    /* we get the key contents into a byte array */
    unsigned char* cert;
    unsigned char* intCert;
    char err[256];
    jboolean rv;
    const unsigned char *tmp;
    jsize lengthOfCert;
    jbyte* bufferPtr = (*e)->GetByteArrayElements(e, javaKey, NULL);
    jsize lengthOfKey = (*e)->GetArrayLength(e, javaKey);
    unsigned char* key = malloc(lengthOfKey);
    tcn_ssl_ctxt_t *c;
    BIO * bio;
    X509* tmpIntCert;
    int intermediateLength;
    jbyteArray byteArray;
    int i;

    memmove(key, bufferPtr, lengthOfKey);
    (*e)->ReleaseByteArrayElements(e, javaKey, bufferPtr, 0);


    bufferPtr = (*e)->GetByteArrayElements(e, javaCert, NULL);
    lengthOfCert = (*e)->GetArrayLength(e, javaCert);
    cert = malloc(lengthOfCert);
    memmove(cert, bufferPtr, lengthOfCert);
    (*e)->ReleaseByteArrayElements(e, javaCert, bufferPtr, 0);


    c = J2P(ctx, tcn_ssl_ctxt_t *);
    rv = JNI_TRUE;

    TCN_ASSERT(ctx != 0);

    if (idx < 0 || idx >= SSL_AIDX_MAX) {
        throwIllegalStateException(e, "Invalid key type");
        rv = JNI_FALSE;
        goto cleanup;
    }
    tmp = (const unsigned char *)cert;
    if ((c->certs[idx] = crypto_methods.d2i_X509(NULL, &tmp, lengthOfCert)) == NULL) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if(c->keys[idx] != NULL) {
        free(c->keys[idx]);
    }

    bio = crypto_methods.BIO_new(crypto_methods.BIO_s_mem());
    crypto_methods.BIO_write(bio, key, lengthOfKey);

    c->keys[idx] = crypto_methods.PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    crypto_methods.BIO_free(bio);
    if (c->keys[idx] == NULL) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if (ssl_methods.SSL_CTX_use_certificate(c->ctx, c->certs[idx]) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error setting certificate (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    /*intermediate certs */
    intermediateLength = (*e)->GetArrayLength(e, intermediateCerts);
    for(i = 0; i < intermediateLength; ++i ) {

        byteArray = (*e)->GetObjectArrayElement(e, intermediateCerts, i);
        bufferPtr = (*e)->GetByteArrayElements(e, byteArray, NULL);
        lengthOfCert = (*e)->GetArrayLength(e, byteArray);
        intCert = malloc(lengthOfCert);
        memmove(intCert, bufferPtr, lengthOfCert);
        (*e)->ReleaseByteArrayElements(e, byteArray, bufferPtr, 0);

        tmp = (const unsigned char *)intCert;


        if ((tmpIntCert = crypto_methods.d2i_X509(NULL, &tmp, lengthOfCert)) == NULL) {
            crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
            throwIllegalStateException(e, err);
            rv = JNI_FALSE;
            free(intCert);
            goto cleanup;
        }

        if (ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)tmpIntCert) <= 0) {
            crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
            tcn_Throw(e, "Error setting certificate (%s)", err);
            rv = JNI_FALSE;
            free(intCert);
            goto cleanup;
        }
        free(intCert);
    }


    if (ssl_methods.SSL_CTX_use_PrivateKey(c->ctx, c->keys[idx]) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error setting private key (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (ssl_methods.SSL_CTX_check_private_key(c->ctx) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Private key does not match the certificate public key (%s)",
                  err);
        rv = JNI_FALSE;
        goto cleanup;
    }


cleanup:
    free(key);
    free(cert);
    return rv;
}


static int SSL_cert_verify(X509_STORE_CTX *ctx, void *arg) {
    unsigned i;
    X509 *cert;
    int length;
    unsigned char *buf;
    JNIEnv *e;
    jbyteArray array;
    jbyteArray bArray;
    jboolean result;
    int r;
    int len;

    /* Get Apache context back through OpenSSL context */
    SSL *ssl = crypto_methods.X509_STORE_CTX_get_ex_data(ctx, ssl_methods.SSL_get_ex_data_X509_STORE_CTX_idx());
    tcn_ssl_ctxt_t *c = SSL_get_app_data2(ssl);
    tcn_ssl_conn_t *conn = SSL_get_app_data1(ssl);


    /*  Get a stack of all certs in the chain */
    STACK_OF_X509 *sk;
    if(crypto_methods.X509_STORE_CTX_get0_untrusted == NULL) {
        sk = ctx->untrusted;
    } else {
        sk = crypto_methods.X509_STORE_CTX_get0_untrusted(ctx);
    }

    len = crypto_methods.sk_num(sk);
    tcn_get_java_env(&e);

    /*  Create the byte[][] array that holds all the certs */
    array = (*e)->NewObjectArray(e, len, byteArrayClass, NULL);

    for(i = 0; i < len; i++) {

        cert = (X509*) crypto_methods.sk_value(sk, i);

        buf = NULL;
        length = crypto_methods.i2d_X509(cert, &buf);
        if (length < 0) {
            /*  In case of error just return an empty byte[][] */
            array = (*e)->NewObjectArray(e, 0, byteArrayClass, NULL);
            /*  We need to delete the local references so we not leak memory as this method is called via callback. */
            crypto_methods.CRYPTO_free(buf);
            break;
        }
        bArray = (*e)->NewByteArray(e, length);
        (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);
        (*e)->SetObjectArrayElement(e, array, i, bArray);

        /*  Delete the local reference as we not know how long the chain is and local references are otherwise */
        /*  only freed once jni method returns. */
        (*e)->DeleteLocalRef(e, bArray);
        crypto_methods.CRYPTO_free(buf);
    }
    result = (*e)->CallBooleanMethod(e, c->verifier, c->verifier_method, P2J(ssl), array,
            conn->server_cipher, conn->server);

    r = result == JNI_TRUE ? 1 : 0;

    /*  We need to delete the local references so we not leak memory as this method is called via callback. */
    (*e)->DeleteLocalRef(e, array);
    return r;
}


WF_OPENSSL(void, setCertVerifyCallback)(JNIEnv *e, jobject o, jlong ctx, jobject verifier)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    if (verifier == NULL) {
        ssl_methods.SSL_CTX_set_cert_verify_callback(c->ctx, NULL, NULL);
    } else {
        jclass verifier_class = (*e)->GetObjectClass(e, verifier);
        jmethodID method = (*e)->GetMethodID(e, verifier_class, "verify", "(J[[BIZ)Z");

        if (method == NULL) {
            return;
        }
        /*  Delete the reference to the previous specified verifier if needed. */
        if (c->verifier != NULL) {
            (*e)->DeleteLocalRef(e, c->verifier);
        }
        c->verifier = (*e)->NewGlobalRef(e, verifier);
        c->verifier_method = method;

        ssl_methods.SSL_CTX_set_cert_verify_callback(c->ctx, SSL_cert_verify, NULL);
    }
}

WF_OPENSSL(jboolean, setSessionIdContext)(JNIEnv *e, jobject o, jlong ctx, jbyteArray sidCtx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int len = (*e)->GetArrayLength(e, sidCtx);
    unsigned char *buf;
    int res;

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    buf = malloc(len);

    (*e)->GetByteArrayRegion(e, sidCtx, 0, len, (jbyte*) buf);

    res = ssl_methods.SSL_CTX_set_session_id_context(c->ctx, buf, len);
    free(buf);

    if (res == 1) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}


static void ssl_info_callback(SSL *ssl, int where, int ret) {
    int *handshakeCount = NULL;
    if (0 != (where & SSL_CB_HANDSHAKE_START)) {
        handshakeCount = (int*) SSL_get_app_data3(ssl);
        if (handshakeCount != NULL) {
            ++(*handshakeCount);
        }
    }
    if (0 != (where & SSL_CB_HANDSHAKE_DONE)) {
        tcn_ssl_conn_t *con = SSL_get_app_data1(ssl);
        con->handshake_done = 1;
    }
}

WF_OPENSSL(jlong, newSSL)(JNIEnv *e, jobject o, jlong ctx /* tcn_ssl_ctxt_t * */, jboolean server) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int *handshakeCount = malloc(sizeof(int));
    SSL *ssl;
    tcn_ssl_conn_t *con;

    UNREFERENCED_STDARGS;

    TCN_ASSERT(ctx != 0);
    ssl = ssl_methods.SSL_new(c->ctx);
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
    con->server = server;

    /* Store the handshakeCount in the SSL instance. */
    *handshakeCount = 0;
    SSL_set_app_data3(ssl, handshakeCount);

    if (server) {
        ssl_methods.SSL_set_accept_state(ssl);
    } else {
        ssl_methods.SSL_set_connect_state(ssl);
    }
    ssl_methods.SSL_set_read_ahead(ssl, 0);

    /* Setup verify and seed */
    if(server == JNI_FALSE) {
        ssl_methods.SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    }
    ssl_methods.SSL_set_verify_result(ssl, X509_V_OK);
    /* Add callback to keep track of handshakes and the handshake state */
    ssl_methods.SSL_set_info_callback(ssl, &ssl_info_callback);

    /* Store for later usage in SSL_callback_SSL_verify */
    SSL_set_app_data1(ssl, con);
    SSL_set_app_data2(ssl, c);
    return P2J(ssl);
}


/* Free the SSL * and its associated internal BIO */
WF_OPENSSL(void, freeSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_ = J2P(ssl, SSL *);
    tcn_ssl_conn_t *con;
    int *handshakeCount = SSL_get_app_data3(ssl_);

    if (handshakeCount != NULL) {
        free(handshakeCount);
    }

    con = SSL_get_app_data1(ssl_);
    if(con->alpn_selection_callback != NULL) {
        (*e)->DeleteGlobalRef(e, con->alpn_selection_callback);
    }
    free(con);
    ssl_methods.SSL_free(ssl_);
}


WF_OPENSSL(jlong, bufferAddress)(JNIEnv *e, jobject o, jobject bb)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED(o);
    if(bb == NULL) {
        throwIllegalArgumentException(e, "Buffer was null");
    }
    return P2J((*e)->GetDirectBufferAddress(e, bb));
}


/* Make a BIO pair (network and internal) for the provided SSL * and return the network BIO */
WF_OPENSSL(jlong, makeNetworkBIO)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_ = J2P(ssl, SSL *);
    BIO *internal_bio;
    BIO *network_bio;

    UNREFERENCED(o);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        goto fail;
    }

    if (crypto_methods.BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0) != 1) {
        throwIllegalStateException(e, "BIO_new_bio_pair failed");
        goto fail;
    }

    ssl_methods.SSL_set_bio(ssl_, internal_bio, internal_bio);

    return P2J(network_bio);
 fail:
    return 0;
}


WF_OPENSSL(jint, doHandshake)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return ssl_methods.SSL_do_handshake(ssl_);
}


WF_OPENSSL(void, saveServerCipher)(JNIEnv *e, jobject o, jlong ssl /* SSL * */, jint server_cipher) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_ = J2P(ssl, SSL *);
    tcn_ssl_conn_t *con;
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }

    UNREFERENCED(o);
    con = SSL_get_app_data1(ssl_);
    con->server_cipher = server_cipher;

}


WF_OPENSSL(jint, getSSLError)(JNIEnv *e, jobject o, jlong ssl, jlong code)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    const SSL *ssl_ = J2P(ssl, SSL *);
    UNREFERENCED(o);
    return ssl_methods.SSL_get_error(ssl_, code);
}

WF_OPENSSL(jint, renegotiate)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_conn_t *con;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);
    con = SSL_get_app_data1(ssl_);
    con->handshake_done = 0;
    ssl_methods.SSL_renegotiate(ssl_);
    return ssl_methods.SSL_do_handshake(ssl_);
}


WF_OPENSSL(jint, getLastErrorNumber)(JNIEnv *e, jobject o) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    return crypto_methods.ERR_get_error();
}

WF_OPENSSL(jint /* nbytes */, pendingWrittenBytesInBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED_STDARGS;

    return crypto_methods.BIO_ctrl_pending(J2P(bio, BIO *));
}

/* How much is available for reading in the given SSL struct? */
WF_OPENSSL(jint, pendingReadableBytesInSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_pending(J2P(ssl, SSL *));
}

/* Write wlen bytes from wbuf into bio */
WF_OPENSSL(jint /* status */, writeToBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */, jlong wbuf /* char* */, jint wlen /* sizeof(wbuf) */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED_STDARGS;

    return crypto_methods.BIO_write(J2P(bio, BIO *), J2P(wbuf, void *), wlen);

}

/* Read up to rlen bytes from bio into rbuf */
WF_OPENSSL(jint /* status */, readFromBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */, jlong rbuf /* char * */, jint rlen /* sizeof(rbuf) - 1 */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED_STDARGS;

    return crypto_methods.BIO_read(J2P(bio, BIO *), J2P(rbuf, void *), rlen);
}

/* Write up to wlen bytes of application data to the ssl BIO (encrypt) */
WF_OPENSSL(jint /* status */, writeToSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */, jlong wbuf /* char * */, jint wlen /* sizeof(wbuf) */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_write(J2P(ssl, SSL *), J2P(wbuf, void *), wlen);
}

/* Read up to rlen bytes of application data from the given SSL BIO (decrypt) */
WF_OPENSSL(jint /* status */, readFromSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */, jlong rbuf /* char * */, jint rlen /* sizeof(rbuf) - 1 */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_read(J2P(ssl, SSL *), J2P(rbuf, void *), rlen);
}

/* Get the shutdown status of the engine */
WF_OPENSSL(jint /* status */, getShutdown)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_get_shutdown(J2P(ssl, SSL *));
}

WF_OPENSSL(jint, isInInit)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED(o);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    } else {
        tcn_ssl_conn_t *con = SSL_get_app_data1(ssl_);
        return con->handshake_done == 0 ? 1 : 0;
    }
}

/* Free a BIO * (typically, the network BIO) */
WF_OPENSSL(void, freeBIO)(JNIEnv *e, jobject o, jlong bio /* BIO * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    BIO *bio_;
    UNREFERENCED_STDARGS;

    bio_ = J2P(bio, BIO *);
    crypto_methods.BIO_free(bio_);
}


WF_OPENSSL(jstring, getErrorString)(JNIEnv *e, jobject o, jlong number)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    char buf[256];
    UNREFERENCED(o);
    crypto_methods.ERR_error_string(number, buf);
    return tcn_new_string(e, buf);
}

/* Read which cipher was negotiated for the given SSL *. */
WF_OPENSSL(jstring, getCipherForSSL)(JNIEnv *e, jobject o, jlong ssl /* SSL * */)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    return AJP_TO_JSTRING(ssl_methods.SSL_CIPHER_get_name(ssl_methods.SSL_get_current_cipher(J2P(ssl, SSL*))));
}


/* Read which protocol was negotiated for the given SSL *. */
WF_OPENSSL(jstring, getVersion)(JNIEnv *e, jobject o, jlong ssl /* SSL * */)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    return AJP_TO_JSTRING(ssl_methods.SSL_get_version(J2P(ssl, SSL*)));
}


WF_OPENSSL(jobjectArray, getPeerCertChain)(JNIEnv *e, jobject o, jlong ssl /* SSL * */)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    STACK_OF_X509 *sk;
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

    /*  Get a stack of all certs in the chain. */
    sk = ssl_methods.SSL_get_peer_cert_chain(ssl_);

    len = crypto_methods.sk_num(sk);
    if (len <= 0) {

        /* No peer certificate chain as no auth took place yet, or the auth was not successful. */
        return NULL;
    }
    /* Create the byte[][] array that holds all the certs */
    array = (*e)->NewObjectArray(e, len, byteArrayClass, NULL);

    for(i = 0; i < len; i++) {
        cert = (X509*) crypto_methods.sk_value(sk, i);

        buf = NULL;
        length = crypto_methods.i2d_X509(cert, &buf);
        if (length < 0) {
            crypto_methods.CRYPTO_free(buf);
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

        crypto_methods.CRYPTO_free(buf);
    }
    return array;
}


/* Send CLOSE_NOTIFY to peer */
WF_OPENSSL(jint , shutdownSSL)(JNIEnv *e, jobject o, jlong ssl) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    return ssl_methods.SSL_shutdown(J2P(ssl, SSL *));
}


WF_OPENSSL(jbyteArray, getPeerCertificate)(JNIEnv *e, jobject o, jlong ssl /* SSL * */)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
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
    cert = ssl_methods.SSL_get_peer_certificate(ssl_);
    if (cert == NULL) {
        return NULL;
    }

    length = crypto_methods.i2d_X509(cert, &buf);

    bArray = (*e)->NewByteArray(e, length);
    (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);

    /*
     * We need to free the cert as the reference count is incremented by one and it is not destroyed when the
     * session is freed.
     * See https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html
     */
    crypto_methods.X509_free(cert);

    crypto_methods.CRYPTO_free(buf);

    return bArray;
}


WF_OPENSSL(jstring, version)(JNIEnv *e)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    char * version = ssl_methods.SSLeay_version(0);
    return (*e)->NewStringUTF(e, version);
}

/* sets up diffie hellman params using the apps/dh2048.pem file from openssl */
void setupDH(JNIEnv *e, SSL_CTX * ctx)
{
BIO *bio;
DH *dh;
static unsigned char dhparams[]={
    0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x44, 0x48, 0x20, 0x50, 0x41, 0x52, 0x41, 0x4D,
    0x45, 0x54, 0x45, 0x52, 0x53, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A, 0x4D, 0x49, 0x49, 0x42, 0x43, 0x41, 0x4B, 0x43,
    0x41, 0x51, 0x45, 0x41, 0x39, 0x6B, 0x4A, 0x58, 0x74, 0x77, 0x68, 0x2F, 0x43, 0x42, 0x64, 0x79, 0x6F, 0x72, 0x72,
    0x57, 0x71, 0x55, 0x4C, 0x7A, 0x42, 0x65, 0x6A, 0x35, 0x55, 0x78, 0x45, 0x35, 0x54, 0x37, 0x62, 0x78, 0x62, 0x72,
    0x6C, 0x4C, 0x4F, 0x43, 0x44, 0x61, 0x41, 0x61, 0x64, 0x57, 0x6F, 0x78, 0x54, 0x70, 0x6A, 0x30, 0x42, 0x56, 0x0A,
    0x38, 0x39, 0x41, 0x48, 0x78, 0x73, 0x74, 0x44, 0x71, 0x5A, 0x53, 0x74, 0x39, 0x30, 0x78, 0x6B, 0x68, 0x6B, 0x6E,
    0x34, 0x44, 0x49, 0x4F, 0x39, 0x5A, 0x65, 0x6B, 0x58, 0x31, 0x4B, 0x48, 0x54, 0x55, 0x50, 0x6A, 0x31, 0x57, 0x56,
    0x2F, 0x63, 0x64, 0x6C, 0x4A, 0x50, 0x50, 0x54, 0x32, 0x4E, 0x32, 0x38, 0x36, 0x5A, 0x34, 0x56, 0x65, 0x53, 0x57,
    0x63, 0x33, 0x39, 0x75, 0x4B, 0x35, 0x30, 0x0A, 0x54, 0x38, 0x58, 0x38, 0x64, 0x72, 0x79, 0x44, 0x78, 0x55, 0x63,
    0x77, 0x59, 0x63, 0x35, 0x38, 0x79, 0x57, 0x62, 0x2F, 0x46, 0x66, 0x6D, 0x37, 0x2F, 0x5A, 0x46, 0x65, 0x78, 0x77,
    0x47, 0x71, 0x30, 0x31, 0x75, 0x65, 0x6A, 0x61, 0x43, 0x6C, 0x63, 0x6A, 0x72, 0x55, 0x47, 0x76, 0x43, 0x2F, 0x52,
    0x67, 0x42, 0x59, 0x4B, 0x2B, 0x58, 0x30, 0x69, 0x50, 0x31, 0x59, 0x54, 0x6B, 0x6E, 0x62, 0x0A, 0x7A, 0x53, 0x43,
    0x30, 0x6E, 0x65, 0x53, 0x52, 0x42, 0x7A, 0x5A, 0x72, 0x4D, 0x32, 0x77, 0x34, 0x44, 0x55, 0x55, 0x64, 0x44, 0x33,
    0x79, 0x49, 0x73, 0x78, 0x78, 0x38, 0x57, 0x79, 0x32, 0x4F, 0x39, 0x76, 0x50, 0x4A, 0x49, 0x38, 0x42, 0x44, 0x38,
    0x4B, 0x56, 0x62, 0x47, 0x49, 0x32, 0x4F, 0x75, 0x31, 0x57, 0x4D, 0x75, 0x46, 0x30, 0x34, 0x30, 0x7A, 0x54, 0x39,
    0x66, 0x42, 0x64, 0x58, 0x0A, 0x51, 0x36, 0x4D, 0x64, 0x47, 0x47, 0x7A, 0x65, 0x4D, 0x79, 0x45, 0x73, 0x74, 0x53,
    0x72, 0x2F, 0x50, 0x4F, 0x47, 0x78, 0x4B, 0x55, 0x41, 0x59, 0x45, 0x59, 0x31, 0x38, 0x68, 0x4B, 0x63, 0x4B, 0x63,
    0x74, 0x61, 0x47, 0x78, 0x41, 0x4D, 0x5A, 0x79, 0x41, 0x63, 0x70, 0x65, 0x73, 0x71, 0x56, 0x44, 0x4E, 0x6D, 0x57,
    0x6E, 0x36, 0x76, 0x51, 0x43, 0x6C, 0x43, 0x62, 0x41, 0x6B, 0x62, 0x54, 0x0A, 0x43, 0x44, 0x31, 0x6D, 0x70, 0x46,
    0x31, 0x42, 0x6E, 0x35, 0x78, 0x38, 0x76, 0x59, 0x6C, 0x4C, 0x49, 0x68, 0x6B, 0x6D, 0x75, 0x71, 0x75, 0x69, 0x58,
    0x73, 0x4E, 0x56, 0x36, 0x54, 0x49, 0x4C, 0x4F, 0x77, 0x49, 0x42, 0x41, 0x67, 0x3D, 0x3D, 0x0A, 0x2D, 0x2D, 0x2D,
    0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x44, 0x48, 0x20, 0x50, 0x41, 0x52, 0x41, 0x4D, 0x45, 0x54, 0x45, 0x52, 0x53,
    0x2D, 0x2D, 0x2D, 0x2D, 0x2D, };
    bio = crypto_methods.BIO_new(crypto_methods.BIO_s_mem());
    if (!bio) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error while configuring DH %s", err);
        return;
    }
    crypto_methods.BIO_write(bio, dhparams, sizeof(dhparams));

    dh = crypto_methods.PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    crypto_methods.BIO_free(bio);
    if (!dh) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error while configuring DH: no DH parameter found (%s)", err);
        return;
    }

    if (1 != ssl_methods.SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)) {
        char err[256];
        crypto_methods.DH_free(dh);
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error while configuring DH: %s", err);
    }

    crypto_methods.DH_free(dh);
}

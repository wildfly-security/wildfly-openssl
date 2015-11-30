/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, JBoss Inc., and individual contributors as indicated
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

#ifndef __UTSSL__
#define __UTSSL__

#define _GNU_SOURCE


/* openssl is deprecated on OSX
   this pragma directive is requires to build it
   otherwise -Wall -Werror fail the build
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <jni.h>
#include <openssl/crypto.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

/* Debugging code */
#if defined(_DEBUG) || defined(DEBUG)
#include <assert.h>
#define TCN_ASSERT(x)  assert((x))
#else
#define TCN_ASSERT(x) (void)0
#endif

/* platform dependent code */
#ifdef WIN32

todo: windows threads
#define LLT(X) (X)

#else

#include <pthread.h>
#define LLT(X) ((long)(X))

#endif


#define P2J(P)          ((jlong)LLT(P))
#define J2P(P, T)       ((T)LLT((jlong)P))
#define J2S(V)  c##V

#define TCN_BEGIN_MACRO     if (1) {
#define TCN_END_MACRO       } else (void)(0)

#define TCN_LOAD_CLASS(E, C, N, R)                  \
    TCN_BEGIN_MACRO                                 \
        jclass _##C = (*(E))->FindClass((E), N);    \
        if (_##C == NULL) {                         \
            (*(E))->ExceptionClear((E));            \
            return R;                               \
        }                                           \
        C = (*(E))->NewGlobalRef((E), _##C);        \
        (*(E))->DeleteLocalRef((E), _##C);          \
    TCN_END_MACRO

#define TCN_UNLOAD_CLASS(E, C)                      \
        (*(E))->DeleteGlobalRef((E), (C))

#define TCN_ALLOC_CSTRING(V)     \
    const char *c##V = V ? (const char *)((*e)->GetStringUTFChars(e, V, 0)) : NULL


#define TCN_FREE_CSTRING(V)      \
    if (c##V) (*e)->ReleaseStringUTFChars(e, V, c##V)

#define TCN_GET_METHOD(E, C, M, N, S, R)            \
    TCN_BEGIN_MACRO                                 \
        M = (*(E))->GetMethodID((E), C, N, S);      \
        if (M == NULL) {                            \
            return R;                               \
        }                                           \
    TCN_END_MACRO

#define UNREFERENCED(V) (V) = (V)
#define UNREFERENCED_STDARGS (e) = (e);(o) = (o);

#define UT_OPENSSL(type, name) JNIEXPORT  type JNICALL Java_io_undertow_openssl_SSL_##name

#define AJP_TO_JSTRING(V)   (*e)->NewStringUTF((e), (V))

#define SSL_CIPHERS_ALWAYS_DISABLED         ("!aNULL:!eNULL:!EXP:")


#define SSL_VERIFY_ERROR_IS_OPTIONAL(errnum) \
   ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) \
    || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) \
    || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) \
    || (errnum == X509_V_ERR_CERT_UNTRUSTED) \
    || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))


/*
 * Adapted from OpenSSL:
 * http://osxr.org/openssl/source/ssl/ssl_locl.h#0291
 */
/* Bits for algorithm_mkey (key exchange algorithm) */
#define SSL_kRSA        0x00000001L /* RSA key exchange */
#define SSL_kDHr        0x00000002L /* DH cert, RSA CA cert */ /* no such ciphersuites supported! */
#define SSL_kDHd        0x00000004L /* DH cert, DSA CA cert */ /* no such ciphersuite supported! */
#define SSL_kEDH        0x00000008L /* tmp DH key no DH cert */
#define SSL_kKRB5       0x00000010L /* Kerberos5 key exchange */
#define SSL_kECDHr      0x00000020L /* ECDH cert, RSA CA cert */
#define SSL_kECDHe      0x00000040L /* ECDH cert, ECDSA CA cert */
#define SSL_kEECDH      0x00000080L /* ephemeral ECDH */
#define SSL_kPSK        0x00000100L /* PSK */
#define SSL_kGOST       0x00000200L /* GOST key exchange */
#define SSL_kSRP        0x00000400L /* SRP */

/* Bits for algorithm_auth (server authentication) */
#define SSL_aRSA        0x00000001L /* RSA auth */
#define SSL_aDSS        0x00000002L /* DSS auth */
#define SSL_aNULL       0x00000004L /* no auth (i.e. use ADH or AECDH) */
#define SSL_aDH         0x00000008L /* Fixed DH auth (kDHd or kDHr) */ /* no such ciphersuites supported! */
#define SSL_aECDH       0x00000010L /* Fixed ECDH auth (kECDHe or kECDHr) */
#define SSL_aKRB5       0x00000020L /* KRB5 auth */
#define SSL_aECDSA      0x00000040L /* ECDSA auth*/
#define SSL_aPSK        0x00000080L /* PSK auth */
#define SSL_aGOST94     0x00000100L /* GOST R 34.10-94 signature auth */
#define SSL_aGOST01     0x00000200L /* GOST R 34.10-2001 signature auth */


#define MAX_ALPN_NPN_PROTO_SIZE 65535

/* OpenSSL end */


#define SSL_AIDX_RSA     (0)
#define SSL_AIDX_DSA     (1)
#define SSL_AIDX_ECC     (3)
#define SSL_AIDX_MAX     (4)

/*
 * Define the SSL options
 */
#define SSL_OPT_NONE            (0)
#define SSL_OPT_RELSET          (1<<0)
#define SSL_OPT_STDENVVARS      (1<<1)
#define SSL_OPT_EXPORTCERTDATA  (1<<3)
#define SSL_OPT_FAKEBASICAUTH   (1<<4)
#define SSL_OPT_STRICTREQUIRE   (1<<5)
#define SSL_OPT_OPTRENEGOTIATE  (1<<6)
#define SSL_OPT_ALL             (SSL_OPT_STDENVVARS|SSL_OPT_EXPORTCERTDATA|SSL_OPT_FAKEBASICAUTH|SSL_OPT_STRICTREQUIRE|SSL_OPT_OPTRENEGOTIATE)

/*
 * Define the SSL Protocol options
 */
#define SSL_PROTOCOL_NONE       (0)
#define SSL_PROTOCOL_SSLV2      (1<<0)
#define SSL_PROTOCOL_SSLV3      (1<<1)
#define SSL_PROTOCOL_TLSV1      (1<<2)
#define SSL_PROTOCOL_TLSV1_1    (1<<3)
#define SSL_PROTOCOL_TLSV1_2    (1<<4)

#define SSL_MODE_CLIENT         (0)
#define SSL_MODE_SERVER         (1)
#define SSL_MODE_COMBINED       (2)

#define SSL_BIO_FLAG_RDONLY     (1<<0)
#define SSL_BIO_FLAG_CALLBACK   (1<<1)
#define SSL_DEFAULT_CACHE_SIZE  (256)
#define SSL_DEFAULT_VHOST_NAME  ("_default_:443")
#define SSL_MAX_STR_LEN         (2048)
#define SSL_MAX_PASSWORD_LEN    (256)

#define SSL_CVERIFY_UNSET           (-1)
#define SSL_CVERIFY_NONE            (0)
#define SSL_CVERIFY_OPTIONAL        (1)
#define SSL_CVERIFY_REQUIRE         (2)
#define SSL_CVERIFY_OPTIONAL_NO_CA  (3)
#define SSL_VERIFY_PEER_STRICT      (SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT)

#define SSL_SHUTDOWN_TYPE_UNSET     (0)
#define SSL_SHUTDOWN_TYPE_STANDARD  (1)
#define SSL_SHUTDOWN_TYPE_UNCLEAN   (2)
#define SSL_SHUTDOWN_TYPE_ACCURATE  (3)

#define SSL_TO_APR_ERROR(X)         (APR_OS_START_USERERR + 1000 + X)

#define SSL_INFO_SESSION_ID                 (0x0001)
#define SSL_INFO_CIPHER                     (0x0002)
#define SSL_INFO_CIPHER_USEKEYSIZE          (0x0003)
#define SSL_INFO_CIPHER_ALGKEYSIZE          (0x0004)
#define SSL_INFO_CIPHER_VERSION             (0x0005)
#define SSL_INFO_CIPHER_DESCRIPTION         (0x0006)
#define SSL_INFO_PROTOCOL                   (0x0007)

#define SSL_INFO_CLIENT_S_DN                (0x0010)
#define SSL_INFO_CLIENT_I_DN                (0x0020)
#define SSL_INFO_SERVER_S_DN                (0x0040)
#define SSL_INFO_SERVER_I_DN                (0x0080)

#define SSL_INFO_DN_COUNTRYNAME             (0x0001)
#define SSL_INFO_DN_STATEORPROVINCENAME     (0x0002)
#define SSL_INFO_DN_LOCALITYNAME            (0x0003)
#define SSL_INFO_DN_ORGANIZATIONNAME        (0x0004)
#define SSL_INFO_DN_ORGANIZATIONALUNITNAME  (0x0005)
#define SSL_INFO_DN_COMMONNAME              (0x0006)
#define SSL_INFO_DN_TITLE                   (0x0007)
#define SSL_INFO_DN_INITIALS                (0x0008)
#define SSL_INFO_DN_GIVENNAME               (0x0009)
#define SSL_INFO_DN_SURNAME                 (0x000A)
#define SSL_INFO_DN_DESCRIPTION             (0x000B)
#define SSL_INFO_DN_UNIQUEIDENTIFIER        (0x000C)
#define SSL_INFO_DN_EMAILADDRESS            (0x000D)

#define SSL_INFO_CLIENT_MASK                (0x0100)

#define SSL_INFO_CLIENT_M_VERSION           (0x0101)
#define SSL_INFO_CLIENT_M_SERIAL            (0x0102)
#define SSL_INFO_CLIENT_V_START             (0x0103)
#define SSL_INFO_CLIENT_V_END               (0x0104)
#define SSL_INFO_CLIENT_A_SIG               (0x0105)
#define SSL_INFO_CLIENT_A_KEY               (0x0106)
#define SSL_INFO_CLIENT_CERT                (0x0107)
#define SSL_INFO_CLIENT_V_REMAIN            (0x0108)

#define SSL_INFO_SERVER_MASK                (0x0200)

#define SSL_INFO_SERVER_M_VERSION           (0x0201)
#define SSL_INFO_SERVER_M_SERIAL            (0x0202)
#define SSL_INFO_SERVER_V_START             (0x0203)
#define SSL_INFO_SERVER_V_END               (0x0204)
#define SSL_INFO_SERVER_A_SIG               (0x0205)
#define SSL_INFO_SERVER_A_KEY               (0x0206)
#define SSL_INFO_SERVER_CERT                (0x0207)
#define SSL_INFO_CLIENT_CERT_CHAIN          (0x0400)

// Use "weak" to redeclare optional features
#define weak __attribute__((weak))


#define TCN_MAX_METHODS 8

typedef struct {
    jobject     obj;
    jmethodID   mid[TCN_MAX_METHODS];
    void        *opaque;
} tcn_callback_t;

typedef struct {
    SSL_CTX         *ctx;
    BIO             *bio_os;
    BIO             *bio_is;

    unsigned char   context_id[SHA_DIGEST_LENGTH];

    int             protocol;
    /* we are one or the other */
    int             mode;

    /* certificate revocation list */
    X509_STORE      *crl;
    /* pointer to the context verify store */
    X509_STORE      *store;
    X509            *certs[SSL_AIDX_MAX];
    EVP_PKEY        *keys[SSL_AIDX_MAX];

    int             ca_certs;
    int             shutdown_type;
    char            *rand_file;

    const char      *cipher_suite;
    /* for client or downstream server authentication */
    int             verify_depth;
    int             verify_mode;

    /* for client: List of protocols to request via ALPN.
     * for server: List of protocols to accept via ALPN.
     */
    /* member alpn is array of protocol strings encoded as a list of bytes
     * of length alpnlen, each protocol string is prepended with a byte
     * containing the protocol string length (max 255), then follows the
     * protocol string itself.
     */
    char            *alpn;
    int             alpnlen;
    /* Add from netty-tcnative */
    /* certificate verifier callback */
    jobject verifier;
    jmethodID verifier_method;

    unsigned char   *next_proto_data;
    unsigned int    next_proto_len;
    int             next_selector_failure_behavior;

    /* Holds the alpn protocols, each of them prefixed with the len of the protocol */
    unsigned char   *alpn_proto_data;
    unsigned int    alpn_proto_len;
    /* End add from netty-tcnative */
    jobject session_context;
} tcn_ssl_ctxt_t;


typedef struct {
    tcn_ssl_ctxt_t *ctx;
    SSL            *ssl;
    X509           *peer;
    int             shutdown_type;
    jobject         alpn_selection_callback;
    /* Track the handshake/renegotiation state for the connection so
     * that all client-initiated renegotiations can be rejected, as a
     * partial fix for CVE-2009-3555.
     */
    enum {
        RENEG_INIT = 0, /* Before initial handshake */
        RENEG_REJECT,   /* After initial handshake; any client-initiated
                         * renegotiation should be rejected
                         */
        RENEG_ALLOW,    /* A server-initated renegotiation is taking
                         * place (as dictated by configuration)
                         */
        RENEG_ABORT     /* Renegotiation initiated by client, abort the
                         * connection
                         */
    } reneg_state;
} tcn_ssl_conn_t;

typedef struct {
    long(*SSLeay)(void) ;
    const char *	(*SSL_CIPHER_get_name)(const SSL_CIPHER *c);
    int (*SSL_CTX_check_private_key)(const SSL_CTX *ctx);
    void	(*SSL_CTX_free)(SSL_CTX *);
    X509_STORE *(*SSL_CTX_get_cert_store)(const SSL_CTX *);
    STACK_OF(X509_NAME) *(*SSL_CTX_get_client_CA_list)(const SSL_CTX *s);
    void (*SSL_CTX_set_client_CA_list)(SSL_CTX *ctx, STACK_OF(X509_NAME) *list);
    long (*SSL_CTX_get_timeout)(const SSL_CTX *ctx);
    int (*SSL_CTX_load_verify_locations)(SSL_CTX *ctx, const char *CAfile, const char *CApath);
    SSL_CTX *(*SSL_CTX_new)(const SSL_METHOD *meth);
    void (*SSL_CTX_sess_set_new_cb)(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess));
    long (*SSL_CTX_callback_ctrl)(SSL_CTX *, int, void (*)(void));
    long (*SSL_CTX_ctrl)(SSL_CTX *ctx, int cmd, long larg, void *parg);
    void *(*SSL_CTX_get_ex_data)(const SSL_CTX *ssl, int idx);
    void (*SSL_CTX_sess_set_remove_cb)(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess));
    int (*SSL_CTX_set_alpn_protos)(SSL_CTX *ctx, const unsigned char *protos, unsigned protos_len);
    void (*SSL_CTX_set_alpn_select_cb)(SSL_CTX *ctx, int (*cb) (SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg), void *arg);
    void (*SSL_CTX_set_cert_verify_callback)(SSL_CTX *ctx, int (*cb) (X509_STORE_CTX *, void *), void *arg);
    int (*SSL_CTX_set_cipher_list)(SSL_CTX *, const char *str);
    int (*SSL_CTX_set_default_verify_paths)(SSL_CTX *ctx);
    int (*SSL_CTX_set_ex_data)(SSL_CTX *ssl, int idx, void *data);
    void (*SSL_CTX_set_info_callback)(SSL_CTX *ctx, void (*cb)(const SSL *ssl,int type,int val));
    int (*SSL_CTX_set_session_id_context)(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
    long (*SSL_CTX_set_timeout)(SSL_CTX *ctx, long t);
    void (*SSL_CTX_set_verify)(SSL_CTX *ctx, int mode, int (*callback)(int, X509_STORE_CTX *));
    int (*SSL_CTX_use_PrivateKey)(SSL_CTX *ctx, EVP_PKEY *pkey);
    int (*SSL_CTX_use_certificate)(SSL_CTX *ctx, X509 *x);
    void (*SSL_SESSION_free)(SSL_SESSION *ses);
    const unsigned char *(*SSL_SESSION_get_id)(const SSL_SESSION *s, unsigned int *len);
    long (*SSL_SESSION_get_time)(const SSL_SESSION *s);
    int	(*SSL_add_file_cert_subjects_to_stack)(STACK_OF(X509_NAME) *stackCAs, const char *file);
    long (*SSL_ctrl)(SSL *ssl, int cmd, long larg, void *parg);
    int (*SSL_do_handshake)(SSL *s);
    void (*SSL_free)(SSL *ssl);
    void (*SSL_get0_alpn_selected)(const SSL *ssl, const unsigned char **data, unsigned *len);
    STACK_OF(SSL_CIPHER) *(*SSL_get_ciphers)(const SSL *s);
    const SSL_CIPHER *(*SSL_get_current_cipher)(const SSL *s);
    void *(*SSL_get_ex_data)(const SSL *ssl, int idx);
    int (*SSL_get_ex_data_X509_STORE_CTX_idx)(void);
    int (*SSL_get_ex_new_index)(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
    STACK_OF(X509) *(*SSL_get_peer_cert_chain)(const SSL *s);
    X509 *(*SSL_get_peer_certificate)(const SSL *s);
    SSL_SESSION *(*SSL_get_session)(const SSL *ssl);
    int (*SSL_get_shutdown)(const SSL *ssl);
    const char *(*SSL_get_version)(const SSL *s);
    int (*SSL_library_init)(void);
    STACK_OF(X509_NAME) *(*SSL_load_client_CA_file)(const char *file);
    void (*SSL_load_error_strings)(void);
    SSL *(*SSL_new)(SSL_CTX *ctx);
    int (*SSL_pending)(const SSL *s);
    int (*SSL_read)(SSL *ssl, void *buf, int num);
    int (*SSL_renegotiate)(SSL *s);
    int (*SSL_renegotiate_pending)(SSL *s);
    SSL_CTX *(*SSL_set_SSL_CTX)(SSL *ssl, SSL_CTX *ctx);
    void (*SSL_set_accept_state)(SSL *s);
    void (*SSL_set_bio)(SSL *s, BIO *rbio, BIO *wbio);
    int (*SSL_set_cipher_list)(SSL *s, const char *str);
    void (*SSL_set_connect_state)(SSL *s);
    int (*SSL_set_ex_data)(SSL *ssl, int idx, void *data);
    void (*SSL_set_verify)(SSL *s, int mode, int (*callback) (int ok, X509_STORE_CTX *ctx));
    void (*SSL_set_verify_result)(SSL *ssl, long v);
    int (*SSL_shutdown)(SSL *s);
    int (*SSL_state)(const SSL *ssl);
    int (*SSL_write)(SSL *ssl, const void *buf, int num);
    const SSL_METHOD *(*SSLv23_client_method)(void);
    const SSL_METHOD *(*SSLv23_method)(void);
    const SSL_METHOD *(*SSLv23_server_method)(void);
    const SSL_METHOD *(*SSLv3_client_method)(void);
    const SSL_METHOD *(*SSLv3_method)(void);
    const SSL_METHOD *(*SSLv3_server_method)(void);
    const SSL_METHOD *(*TLSv1_1_client_method)(void);
    const SSL_METHOD *(*TLSv1_1_method)(void);
    const SSL_METHOD *(*TLSv1_1_server_method)(void);
    const SSL_METHOD *(*TLSv1_2_client_method)(void);
    const SSL_METHOD *(*TLSv1_2_method)(void);
    const SSL_METHOD *(*TLSv1_2_server_method)(void);
    const SSL_METHOD *(*TLSv1_client_method)(void);
    const SSL_METHOD *(*TLSv1_method)(void);
    const SSL_METHOD *(*TLSv1_server_method)(void);
    const SSL_METHOD *(*TLS_server_method)(void);
    const SSL_METHOD *(*TLS_client_method)(void);
    const SSL_METHOD *(*TLS_method)(void);
    struct evp_pkey_st *(*SSL_get_privatekey)(SSL *ssl);
    const char *(*SSL_get_servername)(const SSL *s, const int type);
} ssl_dynamic_methods;

typedef struct {
    int (*ASN1_INTEGER_cmp)(const ASN1_INTEGER *x, const ASN1_INTEGER *y);
    long (*BIO_ctrl)(BIO *bp, int cmd, long larg, void *parg);
    size_t (*BIO_ctrl_pending)(BIO *b);
    int (*BIO_free)(BIO *a);
    BIO *(*BIO_new)(BIO_METHOD *type);
    int (*BIO_new_bio_pair)(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2);
    int (*BIO_printf)(BIO *bio, const char *format, ...);
    int (*BIO_read)(BIO *b, void *data, int len);
    BIO_METHOD *(*BIO_s_file)(void);
    BIO_METHOD *(*BIO_s_mem)(void);
    int (*BIO_write)(BIO *b, const void *data, int len);
    void (*CRYPTO_free)(void *ptr);
    int (*CRYPTO_num_locks)(void);
    void (*CRYPTO_set_dynlock_create_callback)(struct CRYPTO_dynlock_value *(*dyn_create_function)(const char *file, int line));
    void (*CRYPTO_set_dynlock_destroy_callback)(void (*dyn_destroy_function)(struct CRYPTO_dynlock_value *l, const char *file, int line));
    void (*CRYPTO_set_dynlock_lock_callback)(void (*dyn_lock_function)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line));
    void (*CRYPTO_set_id_callback)(unsigned long (*func) (void));
    void (*CRYPTO_set_locking_callback)(void (*func) (int mode, int type,const char *file,int line));
    int (*CRYPTO_set_mem_functions)(void *(*m)(size_t),void *(*r)(void *,size_t), void (*f)(void *));
    char *(*ERR_error_string)(unsigned long e, char *buf);

    unsigned long (*ERR_get_error)(void);
    void (*ERR_load_crypto_strings)(void);
    int (*EVP_Digest)(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);
    int (*EVP_PKEY_bits)(EVP_PKEY *pkey);
    void (*EVP_PKEY_free)(EVP_PKEY *pkey);
    int (*EVP_PKEY_type)(int type);
    const EVP_MD *(*EVP_sha1)(void);
    void (*OPENSSL_add_all_algorithms_noconf)(void);
    void (*OPENSSL_load_builtin_modules)(void);
    EVP_PKEY *(*PEM_read_bio_PrivateKey)(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
    int (*X509_CRL_verify)(X509_CRL *a, EVP_PKEY *r);
    int (*X509_LOOKUP_ctrl)(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret);
    X509_LOOKUP_METHOD *(*X509_LOOKUP_file)(void);
    X509_LOOKUP_METHOD *(*X509_LOOKUP_hash_dir)(void);
    void (*X509_OBJECT_free_contents)(X509_OBJECT *a);
    void (*X509_STORE_CTX_cleanup)(X509_STORE_CTX *ctx);
    X509 *(*X509_STORE_CTX_get_current_cert)(X509_STORE_CTX *ctx);
    int (*X509_STORE_CTX_get_error)(X509_STORE_CTX *ctx);
    int (*X509_STORE_CTX_get_error_depth)(X509_STORE_CTX *ctx);
    void *(*X509_STORE_CTX_get_ex_data)(X509_STORE_CTX *ctx, int idx);
    int (*X509_STORE_CTX_init)(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain);
    void (*X509_STORE_CTX_set_error)(X509_STORE_CTX *ctx, int s);
    X509_LOOKUP *(*X509_STORE_add_lookup)(X509_STORE *v, X509_LOOKUP_METHOD *m);
    void (*X509_STORE_free)(X509_STORE *v);
    int (*X509_STORE_get_by_subject)(X509_STORE_CTX *vs, int type, X509_NAME *name, X509_OBJECT *ret);
    X509_STORE *(*X509_STORE_new)(void);
    int (*X509_STORE_set_flags)(X509_STORE *ctx, unsigned long flags);
    int (*X509_cmp_current_time)(const ASN1_TIME *s);
    X509_NAME *(*X509_get_issuer_name)(X509 *a);
    EVP_PKEY *(*X509_get_pubkey)(X509 *x);
    ASN1_INTEGER *(*X509_get_serialNumber)(X509 *x);
    X509_NAME *(*X509_get_subject_name)(X509 *a);
    BIGNUM *(*get_rfc2409_prime_1024)(BIGNUM *bn);
    BIGNUM *(*get_rfc3526_prime_2048)(BIGNUM *bn);
    BIGNUM *(*get_rfc3526_prime_3072)(BIGNUM *bn);
    BIGNUM *(*get_rfc3526_prime_4096)(BIGNUM *bn);
    BIGNUM *(*get_rfc3526_prime_6144)(BIGNUM *bn);
    BIGNUM *(*get_rfc3526_prime_8192)(BIGNUM *bn);
    int (*sk_num)(const void *);
    void *(*sk_value)(const void *, int);
    void (*X509_free)(X509 *a);
    X509 *(*d2i_X509)(X509 **a, const unsigned char **in, long len);
    int (*i2d_X509)(X509 *a, unsigned char **out);
    void (*ENGINE_load_builtin_engines)(void);
} crypto_dynamic_methods;

void tcn_Throw(JNIEnv *env, char *fmt, ...);
jint throwIllegalStateException( JNIEnv *env, char *message);
jint throwIllegalArgumentException( JNIEnv *env, char *message);
jint tcn_get_java_env(JNIEnv **env);
JavaVM * tcn_get_java_vm();

jstring tcn_new_string(JNIEnv *env, const char *str);
jstring tcn_new_stringn(JNIEnv *env, const char *str, size_t l);
tcn_ssl_ctxt_t *SSL_get_app_data2(SSL *ssl);
void setup_session_context(JNIEnv *e, tcn_ssl_ctxt_t *c);
/*thread setup function*/
void ssl_thread_setup();

void alpn_init(JNIEnv *e);
void session_init(JNIEnv *e);

#endif

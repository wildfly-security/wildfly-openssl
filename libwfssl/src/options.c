
#include "wfssl.h"


extern ssl_dynamic_methods ssl_methods;

/*
 * supported_ssl_opts is a bitmask that contains all supported SSL_OP_*
 * options at compile-time. This is used in hasOp to determine which
 * SSL_OP_* options are available at runtime.
 *
 * Note that at least up through OpenSSL 0.9.8o, checking SSL_OP_ALL will
 * return JNI_FALSE because SSL_OP_ALL is a mask that covers all bug
 * workarounds for OpenSSL including future workarounds that are defined
 * to be in the least-significant 3 nibbles of the SSL_OP_* bit space.
 *
 * This implementation has chosen NOT to simply set all those lower bits
 * so that the return value for SSL_OP_FUTURE_WORKAROUND will only be
 * reported by versions that actually support that specific workaround.
 */
static const jint supported_ssl_opts = 0


/*
  Specifically skip SSL_OP_ALL
#ifdef SSL_OP_ALL
     | SSL_OP_ALL
#endif
*/
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
     | SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#endif

#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
     | SSL_OP_CIPHER_SERVER_PREFERENCE
#endif

#ifdef SSL_OP_CRYPTOPRO_TLSEXT_BUG
     | SSL_OP_CRYPTOPRO_TLSEXT_BUG
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
     | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
#endif

#ifdef SSL_OP_EPHEMERAL_RSA
     | SSL_OP_EPHEMERAL_RSA
#endif

#ifdef SSL_OP_LEGACY_SERVER_CONNECT
     | SSL_OP_LEGACY_SERVER_CONNECT
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
     | SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
#endif

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
     | SSL_OP_MICROSOFT_SESS_ID_BUG
#endif

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
     | SSL_OP_MSIE_SSLV2_RSA_PADDING
#endif

#ifdef SSL_OP_NETSCAPE_CA_DN_BUG
     | SSL_OP_NETSCAPE_CA_DN_BUG
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
     | SSL_OP_NETSCAPE_CHALLENGE_BUG
#endif

#ifdef SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
     | SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
#endif

#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
     | SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
#endif

#ifdef SSL_OP_NO_COMPRESSION
     | SSL_OP_NO_COMPRESSION
#endif

#ifdef SSL_OP_NO_QUERY_MTU
     | SSL_OP_NO_QUERY_MTU
#endif

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
     | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
#endif

#ifdef SSL_OP_NO_SSLv2
     | SSL_OP_NO_SSLv2
#endif

#ifdef SSL_OP_NO_SSLv3
     | SSL_OP_NO_SSLv3
#endif

#ifdef SSL_OP_NO_TICKET
     | SSL_OP_NO_TICKET
#endif

#ifdef SSL_OP_NO_TLSv1
     | SSL_OP_NO_TLSv1
#endif

#ifdef SSL_OP_PKCS1_CHECK_1
     | SSL_OP_PKCS1_CHECK_1
#endif

#ifdef SSL_OP_PKCS1_CHECK_2
     | SSL_OP_PKCS1_CHECK_2
#endif

#ifdef SSL_OP_NO_TLSv1_1
     | SSL_OP_NO_TLSv1_1
#endif

#ifdef SSL_OP_NO_TLSv1_2
     | SSL_OP_NO_TLSv1_2
#endif

#ifdef SSL_OP_SINGLE_DH_USE
     | SSL_OP_SINGLE_DH_USE
#endif

#ifdef SSL_OP_SINGLE_ECDH_USE
     | SSL_OP_SINGLE_ECDH_USE
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
     | SSL_OP_SSLEAY_080_CLIENT_DH_BUG
#endif

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
     | SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
     | SSL_OP_TLS_BLOCK_PADDING_BUG
#endif

#ifdef SSL_OP_TLS_D5_BUG
     | SSL_OP_TLS_D5_BUG
#endif

#ifdef SSL_OP_TLS_ROLLBACK_BUG
     | SSL_OP_TLS_ROLLBACK_BUG
#endif
     | 0;



WF_OPENSSL(jint, getOptions)(JNIEnv *e, jobject o, jlong ssl)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED_STDARGS;

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    }

    return ssl_methods.SSL_get_options(ssl_);
}

WF_OPENSSL(void, setOptions)(JNIEnv *e, jobject o, jlong ssl, jint opt)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED_STDARGS;

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }

#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    /* Clear the flag if not supported */
    if (opt & 0x00040000) {
        opt &= ~0x00040000;
    }
#endif
    ssl_methods.SSL_set_options(ssl_, opt);
}


WF_OPENSSL(jboolean, hasOp)(JNIEnv *e, jobject o, jint op)
{
    return op == (op & supported_ssl_opts) ? JNI_TRUE : JNI_FALSE;
}

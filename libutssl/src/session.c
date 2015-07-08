
#include "utssl.h"

/*functions related to openssl session management */

UT_OPENSSL(jlong, setSessionCacheMode)(JNIEnv *e, jobject o, jlong ctx, jlong mode)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return SSL_CTX_set_session_cache_mode(c->ctx, mode);
}

UT_OPENSSL(jlong, getSessionCacheMode)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return SSL_CTX_get_session_cache_mode(c->ctx);
}

UT_OPENSSL(jlong, setSessionCacheTimeout)(JNIEnv *e, jobject o, jlong ctx, jlong timeout)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_set_timeout(c->ctx, timeout);
    return rv;
}

UT_OPENSSL(jlong, getSessionCacheTimeout)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return SSL_CTX_get_timeout(c->ctx);
}

UT_OPENSSL(jlong, setSessionCacheSize)(JNIEnv *e, jobject o, jlong ctx, jlong size)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = 0;

    // Also allow size of 0 which is unlimited
    if (size >= 0) {
      SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_SERVER);
      rv = SSL_CTX_sess_set_cache_size(c->ctx, size);
    }

    return rv;
}

UT_OPENSSL(jlong, getSessionCacheSize)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return SSL_CTX_sess_get_cache_size(c->ctx);
}

UT_OPENSSL(jlong, sessionNumber)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_number(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionConnect)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_connect(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionConnectGood)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_connect_good(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionConnectRenegotiate)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_connect_renegotiate(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionAccept)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_accept(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionAcceptGood)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_accept_good(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionAcceptRenegotiate)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_accept_renegotiate(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionHits)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_hits(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionCbHits)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_cb_hits(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionMisses)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_misses(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionTimeouts)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_timeouts(c->ctx);
    return rv;
}

UT_OPENSSL(jlong, sessionCacheFull)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = SSL_CTX_sess_cache_full(c->ctx);
    return rv;
}

#define TICKET_KEYS_SIZE 48
UT_OPENSSL(void, setSessionTicketKeys)(JNIEnv *e, jobject o, jlong ctx, jbyteArray keys)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jbyte* b;

    if ((*e)->GetArrayLength(e, keys) != TICKET_KEYS_SIZE) {
        if (c->bio_os) {
            BIO_printf(c->bio_os, "[ERROR] Session ticket keys provided were wrong size.");
        }
        else {
            fprintf(stderr, "[ERROR] Session ticket keys provided were wrong size.");
        }
        exit(1);
    }

    b = (*e)->GetByteArrayElements(e, keys, NULL);
    SSL_CTX_set_tlsext_ticket_keys(c->ctx, b, TICKET_KEYS_SIZE);
    (*e)->ReleaseByteArrayElements(e, keys, b, 0);
}

UT_OPENSSL(jbyteArray, getSessionId)(JNIEnv *e, jobject o, jlong ssl)
{

    unsigned int len;
    const unsigned char *session_id;
    const SSL_SESSION *session;
    jbyteArray bArray;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return NULL;
    }
    session = SSL_get_session(ssl_);
    session_id = SSL_SESSION_get_id(session, &len);

    if (len == 0 || session_id == NULL) {
        return NULL;
    }

    bArray = (*e)->NewByteArray(e, len);
    (*e)->SetByteArrayRegion(e, bArray, 0, len, (jbyte*) session_id);
    return bArray;
}



UT_OPENSSL(void, invalidateSession)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
    SSL_SESSION *session;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }
    session = SSL_get_session(ssl_);
    SSL_SESSION_free(session);
}


UT_OPENSSL(jlong, getTime)(JNIEnv *e, jobject o, jlong ssl)
{
  UNREFERENCED(o);
  SSL_SESSION *session;
  SSL *ssl_ = J2P(ssl, SSL *);
  if (ssl_ == NULL) {
      throwIllegalStateException(e, "ssl is null");
      return 0;
  }
  session = SSL_get_session(ssl_);
  return SSL_get_time(session);
}
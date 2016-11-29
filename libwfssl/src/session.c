
#include "wfssl.h"

/*functions related to openssl session management */


static jclass sessionContextClass;
static jmethodID sessionInit;
static jmethodID sessionRemove;

extern ssl_dynamic_methods ssl_methods;
extern crypto_dynamic_methods crypto_methods;

void session_init(JNIEnv *e) {
    jclass sClazz = (*e)->FindClass(e, "org/wildfly/openssl/OpenSSLSessionContext");
    sessionContextClass = (jclass) (*e)->NewGlobalRef(e, sClazz);
    sessionInit = (*e)->GetMethodID(e, sessionContextClass, "sessionCreatedCallback", "(JJ[B)V");
    sessionRemove = (*e)->GetMethodID(e, sessionContextClass, "sessionRemovedCallback", "([B)V");
}


WF_OPENSSL(jlong, setSessionCacheMode)(JNIEnv *e, jobject o, jlong ctx, jlong mode)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_SESS_CACHE_MODE,mode,NULL);
}

WF_OPENSSL(jlong, getSessionCacheMode)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL);
}

WF_OPENSSL(jlong, setSessionCacheTimeout)(JNIEnv *e, jobject o, jlong ctx, jlong timeout)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_set_timeout(c->ctx, timeout);
    return rv;
}

WF_OPENSSL(jlong, getSessionCacheTimeout)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_get_timeout(c->ctx);
}

WF_OPENSSL(jlong, setSessionCacheSize)(JNIEnv *e, jobject o, jlong ctx, jlong size)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = 0;

    // Also allow size of 0 which is unlimited
    if (size >= 0) {
      ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_SESS_CACHE_MODE,SSL_SESS_CACHE_SERVER,NULL);
      rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,size,NULL);
    }

    return rv;
}

WF_OPENSSL(jlong, getSessionCacheSize)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL);
}

WF_OPENSSL(jlong, sessionNumber)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_NUMBER,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionConnect)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx, SSL_CTRL_SESS_CONNECT,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionConnectGood)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_CONNECT_GOOD,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionConnectRenegotiate)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_CONNECT_RENEGOTIATE,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionAccept)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_ACCEPT,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionAcceptGood)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_ACCEPT_GOOD,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionAcceptRenegotiate)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_ACCEPT_RENEGOTIATE,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionHits)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_HIT,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionCbHits)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_CB_HIT,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionMisses)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_CB_HIT,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionTimeouts)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_TIMEOUTS,0,NULL);
    return rv;
}

WF_OPENSSL(jlong, sessionCacheFull)(JNIEnv *e, jobject o, jlong ctx)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SESS_CACHE_FULL,0,NULL);
    return rv;
}

#define TICKET_KEYS_SIZE 48
WF_OPENSSL(void, setSessionTicketKeys)(JNIEnv *e, jobject o, jlong ctx, jbyteArray keys)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jbyte* b;

    if ((*e)->GetArrayLength(e, keys) != TICKET_KEYS_SIZE) {
        fprintf(stderr, "org.wildfly.openssl [ERROR] Session ticket keys provided were wrong size.");
        exit(1);
    }

    b = (*e)->GetByteArrayElements(e, keys, NULL);
	ssl_methods.SSL_CTX_ctrl((c->ctx),SSL_CTRL_SET_TLSEXT_TICKET_KEYS,(TICKET_KEYS_SIZE),(b));
    (*e)->ReleaseByteArrayElements(e, keys, b, 0);
}

jbyteArray getSessionId(JNIEnv *e, SSL_SESSION *session) {

    unsigned int len;
    const unsigned char *session_id;
    session_id = ssl_methods.SSL_SESSION_get_id(session, &len);

    if (len == 0 || session_id == NULL) {
        return NULL;
    }

    jbyteArray bArray;
    bArray = (*e)->NewByteArray(e, len);
    (*e)->SetByteArrayRegion(e, bArray, 0, len, (jbyte*) session_id);
    return bArray;
}

WF_OPENSSL(jlong, getSession)(JNIEnv *e, jobject o, jlong ssl)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)

    SSL_SESSION *session;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return -1;
    }
    session = ssl_methods.SSL_get1_session(ssl_);
    return P2J(session);
}

WF_OPENSSL(void, setSession)(JNIEnv *e, jobject o, jlong ssl, jlong session)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)

    SSL_SESSION *session_ = J2P(session, SSL_SESSION *);
    if (session_ == NULL) {
        throwIllegalStateException(e, "session is null");
    }
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
    }
    int r = ssl_methods.SSL_set_session(ssl_, session_);
    if (r == 0) {
        fprintf(stderr, "org.wildfly.openssl [ERROR] %s", crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), NULL));
    }
}

WF_OPENSSL(jbyteArray, getSessionId)(JNIEnv *e, jobject o, jlong ssl)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)

    SSL_SESSION *session;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return NULL;
    }
    session = ssl_methods.SSL_get_session(ssl_);
    return getSessionId(e, session);
}
WF_OPENSSL(jlong, getSessionPointer)(JNIEnv *e, jobject o, jlong ssl)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)

    SSL_SESSION *session;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return 0;
    }
    session = ssl_methods.SSL_get_session(ssl_);
    return P2J(session);
}


WF_OPENSSL(void, invalidateSession)(JNIEnv *e, jobject o, jlong ses) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL_SESSION *session = J2P(ses, SSL_SESSION *);
    if (session == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }
    ssl_methods.SSL_SESSION_free(session);
}


WF_OPENSSL(jlong, getTime)(JNIEnv *e, jobject o, jlong ssl)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
  UNREFERENCED(o);
  SSL_SESSION *session;
  SSL *ssl_ = J2P(ssl, SSL *);
  if (ssl_ == NULL) {
      throwIllegalStateException(e, "ssl is null");
      return 0;
  }
  session = ssl_methods.SSL_get_session(ssl_);
  return ssl_methods.SSL_SESSION_get_time(session);
}

WF_OPENSSL(void, registerSessionContext)(JNIEnv *e, jobject o, jlong ctx, jobject context) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    c->session_context = (*e)->NewGlobalRef(e, context);
}

int new_session_cb(SSL * ssl, SSL_SESSION * session) {
    tcn_ssl_ctxt_t  *c = SSL_get_app_data2(ssl);

    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *e;
    (*javavm)->AttachCurrentThread(javavm, (void **)&e, NULL);
    jbyteArray sessionId = getSessionId(e, session);

    (*e)->CallVoidMethod(e, c->session_context, sessionInit, ssl, session, sessionId);

    (*javavm)->DetachCurrentThread(javavm);
    return 1;
}
void remove_session_cb(SSL_CTX *ctx, SSL_SESSION * session) {
     tcn_ssl_ctxt_t  *c = SSL_CTX_get_app_data1(ctx);
    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *e;
    (*javavm)->AttachCurrentThread(javavm, (void **)&e, NULL);
    jbyteArray sessionId = getSessionId(e, session);

    (*e)->CallVoidMethod(e, c->session_context, sessionRemove, sessionId);

    (*javavm)->DetachCurrentThread(javavm);
}

void setup_session_context(JNIEnv *e, tcn_ssl_ctxt_t *c) {
 /* Default session context id and cache size */
    ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,SSL_DEFAULT_CACHE_SIZE,NULL);
    /* Session cache is disabled by default */
	ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_SESS_CACHE_MODE,SSL_SESS_CACHE_OFF,NULL);
    /* Longer session timeout */
    ssl_methods.SSL_CTX_set_timeout(c->ctx, 14400);

    ssl_methods.SSL_CTX_sess_set_new_cb(c->ctx, &new_session_cb);
    ssl_methods.SSL_CTX_sess_set_remove_cb(c->ctx, &remove_session_cb);
}



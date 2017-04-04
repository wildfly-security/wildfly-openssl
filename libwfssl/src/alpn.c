
#include "wfssl.h"

static jclass stringClass;
static jmethodID stringEquals;
extern ssl_dynamic_methods ssl_methods;

WF_OPENSSL(void, setAlpnProtos)(JNIEnv *e, jobject o, jlong ssl, jobjectArray alpn_protos);
WF_OPENSSL(void, enableAlpn)(JNIEnv *e, jobject o, jlong ctx);
WF_OPENSSL(jstring, getAlpnSelected)(JNIEnv *e, jobject o, jlong ssl /* SSL * */);
WF_OPENSSL(void, setServerALPNCallback)(JNIEnv *e, jobject o, jlong ssl, jobject callback);
WF_OPENSSL(jboolean, isAlpnSupported)(JNIEnv *e, jobject o);
int SSL_callback_alpn_select_proto(SSL* ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *arg);

void alpn_init(JNIEnv *e) {
    jclass sClazz = (*e)->FindClass(e, "java/lang/String");
    stringClass = (jclass) (*e)->NewGlobalRef(e, sClazz);
    stringEquals = (*e)->GetMethodID(e, stringClass, "equals", "(Ljava/lang/Object;)Z");
}

/* Convert protos to wire format */
static int initProtocols(JNIEnv *e, unsigned char **proto_data,
            unsigned int *proto_len, jobjectArray protos) {
    int i;
    unsigned char *p_data;
    /*
     * We start with allocate 128 bytes which should be good enough for most use-cases while still be pretty low.
     * We will call realloc to increate this if needed.
     */
    size_t p_data_size = 128;
    size_t p_data_len = 0;
    jstring proto_string;
    const char *proto_chars;
    size_t proto_chars_len;
    int cnt;

    if (protos == NULL) {
        /*  Guard against NULL protos. */
        return -1;
    }

    cnt = (*e)->GetArrayLength(e, protos);

    if (cnt == 0) {
        /*  if cnt is 0 we not need to continue and can just fail fast. */
        return -1;
    }

    p_data = (unsigned char *) malloc(p_data_size);
    if (p_data == NULL) {
        /*  Not enough memory? */
        return -1;
    }

    for (i = 0; i < cnt; ++i) {
         proto_string = (jstring) (*e)->GetObjectArrayElement(e, protos, i);
         proto_chars = (*e)->GetStringUTFChars(e, proto_string, 0);

         proto_chars_len = strlen(proto_chars);
         if (proto_chars_len > 0 && proto_chars_len <= MAX_ALPN_NPN_PROTO_SIZE) {
            /* We need to add +1 as each protocol is prefixed by it's length (unsigned char).
             * For all except of the last one we already have the extra space as everything is
             * delimited by ','. */
            p_data_len += 1 + proto_chars_len;
            if (p_data_len > p_data_size) {
                /*  double size */
                p_data_size <<= 1;
                p_data = realloc(p_data, p_data_size);
                if (p_data == NULL) {
                    /*  Not enough memory? */
                    (*e)->ReleaseStringUTFChars(e, proto_string, proto_chars);
                    break;
                }
            }
            /*  Write the length of the protocol and then increment before memmove the protocol itself. */
            *p_data = proto_chars_len;
            ++p_data;
            memmove(p_data, proto_chars, proto_chars_len);
            p_data += proto_chars_len;
         }

         /*  Release the string to prevent memory leaks */
         (*e)->ReleaseStringUTFChars(e, proto_string, proto_chars);
    }

    if (p_data == NULL) {
        /*  Something went wrong so update the proto_len and return -1 */
        *proto_len = 0;
        return -1;
    } else {
        if (*proto_data != NULL) {
            /*  Free old data */
            free(*proto_data);
        }
        /*  Decrement pointer again as we incremented it while creating the protocols in wire format. */
        p_data -= p_data_len;
        *proto_data = p_data;
        *proto_len = p_data_len;
        return 0;
    }
}

int SSL_callback_alpn_select_proto(SSL* ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *arg) {
    JavaVM *javavm;
    JNIEnv *e;
    jobjectArray array;
    jobject *nativeArray;
    jclass clazz;
    jmethodID method;
    jobject result;
    int count;
    const unsigned char *p;
    const unsigned char *end;
    const unsigned char *proto;
    unsigned char proto_len;
    int c;


    tcn_ssl_conn_t *con = SSL_get_app_data1(ssl);

    if(con->alpn_selection_callback == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* Get the JNI environment for this callback */
    javavm = tcn_get_java_vm();
    (*javavm)->AttachCurrentThread(javavm, (void **)&e, NULL);

    p = in;
    end = in + inlen;
    /* first we count them */
    count = 0;
    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            count++;
        }
        /*  Move on to the next protocol. */
        p += proto_len;
    }
    /* now we allocate an array */
    array = (*e)->NewObjectArray(e, count, stringClass, NULL);
    nativeArray = malloc(count * sizeof(jobject));
    p = in;
    end = in + inlen;
    c = 0;

    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            jobject string = tcn_new_stringn(e, (const char*)proto, proto_len);
            nativeArray[c] = string;
            (*e)->SetObjectArrayElement(e, array, c++, string);
        }
        /*  Move on to the next protocol. */
        p += proto_len;
    }

    clazz = (*e)->GetObjectClass(e, con->alpn_selection_callback);
    method = (*e)->GetMethodID(e, clazz, "select", "([Ljava/lang/String;)Ljava/lang/String;");
    result = (*e)->CallObjectMethod(e, con->alpn_selection_callback, method, array);

    if(result == NULL) {
        (*javavm)->DetachCurrentThread(javavm);
		free(nativeArray);
        return SSL_TLSEXT_ERR_NOACK;
    }

    p = in;
    end = in + inlen;
    c = 0;
    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            jobject string = nativeArray[c++];
            if((*e)->CallBooleanMethod(e, string, stringEquals, result)) {

                /* we have a match */
                *out = proto;
                *outlen = proto_len;
                (*javavm)->DetachCurrentThread(javavm);
				free(nativeArray);
                return SSL_TLSEXT_ERR_OK;
            }
        }
        /*  Move on to the next protocol. */
        p += proto_len;
    }

    /* it did not return a valid response */
    (*javavm)->DetachCurrentThread(javavm);
	free(nativeArray);
    return SSL_TLSEXT_ERR_NOACK;

}

WF_OPENSSL(void, setAlpnProtos)(JNIEnv *e, jobject o, jlong ssl, jobjectArray alpn_protos)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_;
    unsigned char * alpn_proto_data;
    unsigned int alpn_proto_len;
    if(ssl_methods.SSL_set_alpn_protos == NULL) {
        return;
    }
    ssl_ = J2P(ssl, SSL *);

    TCN_ASSERT(ssl != 0);
    alpn_proto_data = NULL;
    alpn_proto_len = 0;
    if (initProtocols(e, &alpn_proto_data, &alpn_proto_len, alpn_protos) == 0) {
        ssl_methods.SSL_set_alpn_protos(ssl_, alpn_proto_data, alpn_proto_len);
        free(alpn_proto_data);
    }
}


WF_OPENSSL(void, enableAlpn)(JNIEnv *e, jobject o, jlong ctx)
{

#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c;
    if(ssl_methods.SSL_set_alpn_protos == NULL) {
        return;
    }
    c = J2P(ctx, tcn_ssl_ctxt_t *);

    TCN_ASSERT(ctx != 0);

    ssl_methods.SSL_CTX_set_alpn_select_cb(c->ctx, SSL_callback_alpn_select_proto, (void *) c);

}


WF_OPENSSL(jstring, getAlpnSelected)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_ = J2P(ssl, SSL *);
    const unsigned char *proto;
    unsigned int proto_len;

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return NULL;
    }
    if(ssl_methods.SSL_get0_alpn_selected == NULL) {
        return NULL;
    }

    UNREFERENCED(o);

    ssl_methods.SSL_get0_alpn_selected(ssl_, &proto, &proto_len);
    return tcn_new_stringn(e, (const char *) proto, (size_t) proto_len);
}

WF_OPENSSL(void, setServerALPNCallback)(JNIEnv *e, jobject o, jlong ssl, jobject callback) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    SSL *ssl_;
    tcn_ssl_conn_t *con;
    if(ssl_methods.SSL_set_alpn_protos == NULL) {
        return;
    }
    ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }
    con = SSL_get_app_data1(ssl_);

    con->alpn_selection_callback = (*e)->NewGlobalRef(e, callback);
}

WF_OPENSSL(jboolean, isAlpnSupported)(JNIEnv *e, jobject o) {
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    return ssl_methods.SSL_set_alpn_protos != NULL;
}

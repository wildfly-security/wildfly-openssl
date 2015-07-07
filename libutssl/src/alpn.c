
#include "utssl_private.h"

#define SSL_SELECTOR_FAILURE_CHOOSE_MY_LAST_PROTOCOL            1

static jclass stringClass;
static jmethodID stringEquals;

void alpn_init(JNIEnv *e) {
    jclass sClazz = (*e)->FindClass(e, "java/lang/String");

    stringClass = (jclass) (*e)->NewGlobalRef(e, sClazz);
    stringEquals = (*e)->GetMethodID(e, stringClass, "equals", "(Ljava/lang/Object;)Z");
}

/* Convert protos to wire format */
static int initProtocols(JNIEnv *e, const tcn_ssl_ctxt_t *c, unsigned char **proto_data,
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
        // Guard against NULL protos.
        return -1;
    }

    cnt = (*e)->GetArrayLength(e, protos);

    if (cnt == 0) {
        // if cnt is 0 we not need to continue and can just fail fast.
        return -1;
    }

    p_data = (unsigned char *) malloc(p_data_size);
    if (p_data == NULL) {
        // Not enough memory?
        return -1;
    }

    for (i = 0; i < cnt; ++i) {
         proto_string = (jstring) (*e)->GetObjectArrayElement(e, protos, i);
         proto_chars = (*e)->GetStringUTFChars(e, proto_string, 0);

         proto_chars_len = strlen(proto_chars);
         if (proto_chars_len > 0 && proto_chars_len <= MAX_ALPN_NPN_PROTO_SIZE) {
            // We need to add +1 as each protocol is prefixed by it's length (unsigned char).
            // For all except of the last one we already have the extra space as everything is
            // delimited by ','.
            p_data_len += 1 + proto_chars_len;
            if (p_data_len > p_data_size) {
                // double size
                p_data_size <<= 1;
                p_data = realloc(p_data, p_data_size);
                if (p_data == NULL) {
                    // Not enough memory?
                    (*e)->ReleaseStringUTFChars(e, proto_string, proto_chars);
                    break;
                }
            }
            // Write the length of the protocol and then increment before memcpy the protocol itself.
            *p_data = proto_chars_len;
            ++p_data;
            memcpy(p_data, proto_chars, proto_chars_len);
            p_data += proto_chars_len;
         }

         // Release the string to prevent memory leaks
         (*e)->ReleaseStringUTFChars(e, proto_string, proto_chars);
    }

    if (p_data == NULL) {
        // Something went wrong so update the proto_len and return -1
        *proto_len = 0;
        return -1;
    } else {
        if (*proto_data != NULL) {
            // Free old data
            free(*proto_data);
        }
        // Decrement pointer again as we incremented it while creating the protocols in wire format.
        p_data -= p_data_len;
        *proto_data = p_data;
        *proto_len = p_data_len;
        return 0;
    }
}


/* The code here is inspired by nghttp2
 *
 * See https://github.com/tatsuhiro-t/nghttp2/blob/ae0100a9abfcf3149b8d9e62aae216e946b517fb/src/shrpx_ssl.cc#L244 */
int select_next_proto(SSL *ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, unsigned char *supported_protos,
        unsigned int supported_protos_len, int failure_behavior) {

    unsigned int i = 0;
    unsigned char target_proto_len;
    const unsigned char *p;
    const unsigned char *end;
    const unsigned char *proto;
    unsigned char proto_len;

    while (i < supported_protos_len) {
        target_proto_len = *supported_protos;
        ++supported_protos;

        p = in;
        end = in + inlen;

        while (p < end) {
            proto_len = *p;
            proto = ++p;

            if (proto + proto_len <= end && target_proto_len == proto_len &&
                    memcmp(supported_protos, proto, proto_len) == 0) {

                // We found a match, so set the output and return with OK!
                *out = proto;
                *outlen = proto_len;

                return SSL_TLSEXT_ERR_OK;
            }
            // Move on to the next protocol.
            p += proto_len;
        }

        // increment len and pointers.
        i += target_proto_len;
        supported_protos += target_proto_len;
    }

    if (failure_behavior == SSL_SELECTOR_FAILURE_CHOOSE_MY_LAST_PROTOCOL) {
         // There were no match but we just select our last protocol and hope the other peer support it.
         //
         // decrement the pointer again so the pointer points to the start of the protocol.
         p -= proto_len;
         *out = p;
         *outlen = proto_len;
         return SSL_TLSEXT_ERR_OK;
    }
    // TODO: OpenSSL currently not support to fail with fatal error. Once this changes we can also support it here.
    //       Issue https://github.com/openssl/openssl/issues/188 has been created for this.
    // Nothing matched so not select anything and just accept.
    return SSL_TLSEXT_ERR_NOACK;
}

int SSL_callback_alpn_select_proto(SSL* ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *arg) {
    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)SSL_get_app_data(ssl);

    if(con->alpn_selection_callback == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* Get the JNI environment for this callback */
    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *e;
    (*javavm)->AttachCurrentThread(javavm, (void **)&e, NULL);

    const unsigned char *p;
    const unsigned char *end;
    const unsigned char *proto;
    unsigned char proto_len;

    p = in;
    end = in + inlen;
    //first we count them
    int count = 0;
    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            count++;
        }
        // Move on to the next protocol.
        p += proto_len;
    }
    //now we allocate an array
    jobjectArray array = (*e)->NewObjectArray(e, count, stringClass, NULL);
    jobject nativeArray[count];
    p = in;
    end = in + inlen;
    int c = 0;

    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            jobject string = tcn_new_stringn(e, (const char*)proto, proto_len);
            nativeArray[c] = string;
            (*e)->SetObjectArrayElement(e, array, c++, string);
        }
        // Move on to the next protocol.
        p += proto_len;
    }

    jclass clazz = (*e)->GetObjectClass(e, con->alpn_selection_callback);
    jmethodID method = (*e)->GetMethodID(e, clazz, "select", "([Ljava/lang/String;)Ljava/lang/String;");
    jobject result = (*e)->CallObjectMethod(e, con->alpn_selection_callback, method, array);

    if(result == NULL) {
        (*javavm)->DetachCurrentThread(javavm);
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
            printf("now proto %s \n",(char *)proto);
            if((*e)->CallBooleanMethod(e, string, stringEquals, result)) {
                printf("m");

                //we have a match
                *out = proto;
                *outlen = proto_len;
                (*javavm)->DetachCurrentThread(javavm);
                return SSL_TLSEXT_ERR_OK;
            }
        }
        // Move on to the next protocol.
        p += proto_len;
    }

    //it did not return a valid response
    (*javavm)->DetachCurrentThread(javavm);
    return SSL_TLSEXT_ERR_NOACK;

}

UT_OPENSSL(void, setAlpnProtos)(JNIEnv *e, jobject o, jlong ctx, jobjectArray alpn_protos,
        jint selectorFailureBehavior)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    TCN_ASSERT(ctx != 0);
    UNREFERENCED(o);

    if (initProtocols(e, c, &c->alpn_proto_data, &c->alpn_proto_len, alpn_protos) == 0) {
        SSL_CTX_set_alpn_protos(c->ctx, c->alpn_proto_data, c->alpn_proto_len);
    }
}


UT_OPENSSL(void, enableAlpn)(JNIEnv *e, jobject o, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    TCN_ASSERT(ctx != 0);
    UNREFERENCED(o);

    SSL_CTX_set_alpn_select_cb(c->ctx, SSL_callback_alpn_select_proto, (void *) c);

}


UT_OPENSSL(jstring, getAlpnSelected)(JNIEnv *e, jobject o, jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    const unsigned char *proto;
    unsigned int proto_len;

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    SSL_get0_alpn_selected(ssl_, &proto, &proto_len);
    return tcn_new_stringn(e, (const char *) proto, (size_t) proto_len);
}

UT_OPENSSL(void, setServerALPNCallback)(JNIEnv *e, jobject o, jlong ssl, jobject callback) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }
    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)SSL_get_app_data(ssl_);

    con->alpn_selection_callback = (*e)->NewGlobalRef(e, callback);
}
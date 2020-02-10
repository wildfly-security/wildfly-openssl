
#include "wfssl.h"



static JavaVM     *tcn_global_vm = NULL;

static jclass    jString_class;
static jmethodID jString_init;
static jmethodID jString_getBytes;
#define TCN_PARENT_IDE  "TCN_PARENT_ID"

int tcn_parent_pid = 0;

extern ssl_dynamic_methods ssl_methods;
extern crypto_dynamic_methods crypto_methods;

/* Called by the JVM when APR_JAVA is loaded */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    void   *ppe;

    if ((*vm)->GetEnv(vm, &ppe, JNI_VERSION_1_4)) {
        return JNI_ERR;
    }
    tcn_global_vm = vm;
    env           = (JNIEnv *)ppe;

    /* Initialize global java.lang.String class */
    TCN_LOAD_CLASS(env, jString_class, "java/lang/String", JNI_ERR);

    TCN_GET_METHOD(env, jString_class, jString_init,
                   "<init>", "([B)V", JNI_ERR);
    TCN_GET_METHOD(env, jString_class, jString_getBytes,
                   "getBytes", "()[B", JNI_ERR);
#ifdef WIN32
    {
        char *ppid = getenv(TCN_PARENT_IDE);
        if (ppid)
            tcn_parent_pid = atoi(ppid);
    }
#else
    tcn_parent_pid = getppid();
#endif

    return  JNI_VERSION_1_4;
}


/* Called by the JVM before the APR_JAVA is unloaded */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    void   *ppe;

    if ((*vm)->GetEnv(vm, &ppe, JNI_VERSION_1_2)) {
        return;
    }
    if (jString_class) {
        env  = (JNIEnv *)ppe;
        TCN_UNLOAD_CLASS(env, jString_class);
    }
}


jint throwIllegalStateException( JNIEnv *env, char *message )
{
    jclass exClass;
    char *className = "java/lang/IllegalStateException";

    exClass = (*env)->FindClass( env, className);
    return (*env)->ThrowNew( env, exClass, message );
}


jint throwIllegalArgumentException( JNIEnv *env, char *message )
{
    jclass exClass;
    char *className = "java/lang/IllegalArgumentException";

    exClass = (*env)->FindClass( env, className);
    return (*env)->ThrowNew( env, exClass, message );
}

#define DP_S_DEFAULT 0
#define DP_S_CONV    1
#define DP_S_DONE    2

static void dopr_outch(char *buffer, int *currlen, int maxlen, char c) {
    if (*currlen < maxlen) {
        buffer[(*currlen)] = c;
    }
    (*currlen)++;
}

static void fmtstr(char *buffer, int *currlen, size_t maxlen, char *value) {
    if (value == 0) {
        value = (char*)"<NULL>";
    }

    while (*value && *currlen < maxlen) {
        dopr_outch(buffer, currlen, maxlen, *value++);
    }
}

#define MSG_MAXLEN 4096

void tcn_Throw(JNIEnv *env, char *fmt, ...) {
    char msg[MSG_MAXLEN];
    va_list ap;
    char ch;
    int state;
    int currlen;
    char *strvalue;

    va_start(ap, fmt);

    /* TODO: no vsprintf in some envs. Short format function
     *       that just prints %s options
     *       (all other options are skipped)
     */
    state = DP_S_DEFAULT;
    ch = *fmt++;
    currlen = 0;
    while (state != DP_S_DONE) {
        if (ch == '\0') {
            state = DP_S_DONE;
        }

        switch(state) {
            case DP_S_DEFAULT:
                if (ch == '%')
                    state = DP_S_CONV;
                else
                    dopr_outch(msg, &currlen, MSG_MAXLEN, ch);
                ch = *fmt++;
                break;
            case DP_S_CONV:
                switch (ch) {
                    case 's':
                        strvalue = va_arg(ap, char *);
                        fmtstr(msg, &currlen, MSG_MAXLEN, strvalue);
                        break;
                    default:
                        break;
                }
                ch = *fmt++;
                state = DP_S_DEFAULT;
                break;
            case DP_S_DONE:
            default:
                break;
        }
    }
    if (currlen < MSG_MAXLEN - 1) {
        msg[currlen] = '\0';
    } else {
        msg[MSG_MAXLEN - 1] = '\0';
    }

    va_end(ap);
    throwIllegalStateException(env, msg);
}

jint tcn_get_java_env(JNIEnv **env)
{
    if ((*tcn_global_vm)->GetEnv(tcn_global_vm, (void **)env,
                                 JNI_VERSION_1_4)) {
        return JNI_ERR;
    }
    return JNI_OK;
}


JavaVM * tcn_get_java_vm()
{
    return tcn_global_vm;
}


jstring tcn_new_string(JNIEnv *env, const char *str)
{
    if (!str)
        return NULL;
    else
        return (*env)->NewStringUTF(env, str);
}

jstring tcn_new_stringn(JNIEnv *env, const char *str, size_t l)
{
    jstring result;
    jbyteArray bytes = 0;

    if (!str)
        return NULL;
    if ((*env)->EnsureLocalCapacity(env, 2) < 0) {
        return NULL; /* out of memory error */
    }
    bytes = (*env)->NewByteArray(env, l);
    if (bytes != NULL) {
        (*env)->SetByteArrayRegion(env, bytes, 0, l, (jbyte *)str);
        result = (*env)->NewObject(env, jString_class, jString_init, bytes);
        (*env)->DeleteLocalRef(env, bytes);
        return result;
    } /* else fall through */
    return NULL;
}

void generate_openssl_stack_error(JNIEnv *e, char *buf, long len) {
    BIO *bio;
    char *bio_buf;
    long bio_len;

    bio = crypto_methods.BIO_new(crypto_methods.BIO_s_mem());
    if (bio == NULL) {
        throwIllegalStateException(e, "Failed to allocate BIO");
    }
    crypto_methods.ERR_print_errors(bio);
    bio_len = BIO_get_mem_data(bio, &bio_buf);
    if (bio_len > len) {
        bio_len = len;
    }
    memmove(buf, bio_buf, bio_len);
    buf[bio_len] = '\0';
    crypto_methods.BIO_free(bio);
}

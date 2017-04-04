#include "wfssl.h"

extern ssl_dynamic_methods ssl_methods;
extern crypto_dynamic_methods crypto_methods;

/*
 * This OpenSSL callback function is called when OpenSSL
 * does client authentication and verifies the certificate chain.
 */
int SSL_callback_SSL_verify(int ok, X509_STORE_CTX *ctx)
{
   /* Get Apache context back through OpenSSL context */
    SSL *ssl = crypto_methods.X509_STORE_CTX_get_ex_data(ctx,
                                          ssl_methods.SSL_get_ex_data_X509_STORE_CTX_idx());
    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)ssl_methods.SSL_get_ex_data(ssl, 0);
    /* Get verify ingredients */
    int errnum   = crypto_methods.X509_STORE_CTX_get_error(ctx);
    int errdepth = crypto_methods.X509_STORE_CTX_get_error_depth(ctx);
    int verify   = con->ctx->verify_mode;
    int depth    = con->ctx->verify_depth;
    int skip_crl = 0;

    if (verify == SSL_CVERIFY_UNSET ||
        verify == SSL_CVERIFY_NONE)
        return 1;

    if (SSL_VERIFY_ERROR_IS_OPTIONAL(errnum) &&
        (verify == SSL_CVERIFY_OPTIONAL_NO_CA)) {
        ok = 1;
        ssl_methods.SSL_set_verify_result(ssl, X509_V_OK);
    }

#ifdef HAVE_OCSP_STAPLING
    /* First perform OCSP validation if possible */
    if (ok) {
        /* If there was an optional verification error, it's not
         * possible to perform OCSP validation since the issuer may be
         * missing/untrusted.  Fail in that case.
         */
        if (SSL_VERIFY_ERROR_IS_OPTIONAL(errnum)) {
            crypto_methods.X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
            errnum = X509_V_ERR_APPLICATION_VERIFICATION;
            ok = 0;
        }
        else {
            int ocsp_response = ssl_verify_OCSP(ok, ctx);
            if (ocsp_response == OCSP_STATUS_OK) {
                skip_crl = 1; /* we know it is valid we skip crl evaluation */
            }
            else if (ocsp_response == OCSP_STATUS_REVOKED) {
                ok = 0 ;
                errnum = crypto_methods.X509_STORE_CTX_get_error(ctx);
            }
            else if (ocsp_response == OCSP_STATUS_UNKNOWN) {
                /* TODO: do nothing for time being, continue with CRL */
                ;
            }
        }
    }
#endif
    /*
     * If we already know it's not ok, log the real reason
     */
    if (!ok) {
        /* TODO: Some logging
         * Certificate Verification: Error
         */
        if (con->peer) {
            crypto_methods.X509_free(con->peer);
            con->peer = NULL;
        }
    }
    if (errdepth > depth) {
        /* TODO: Some logging
         * Certificate Verification: Certificate Chain too long
         */
        ok = 0;
    }
    return ok;
}

WF_OPENSSL(void, setSSLVerify)(JNIEnv *e, jobject o, jlong ssl, jint level, jint depth)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    tcn_ssl_ctxt_t *c;
    int verify;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }

    c = SSL_get_app_data2(ssl_);

    verify = SSL_VERIFY_NONE;

    UNREFERENCED(o);
    c->verify_mode = level;

    if (c->verify_mode == SSL_CVERIFY_UNSET)
        c->verify_mode = SSL_CVERIFY_NONE;
    if (depth > 0)
        c->verify_depth = depth;
    /*
     *  Configure callbacks for SSL context
     */
    if (c->verify_mode == SSL_CVERIFY_REQUIRE)
        verify |= SSL_VERIFY_PEER_STRICT;
    if ((c->verify_mode == SSL_CVERIFY_OPTIONAL) ||
        (c->verify_mode == SSL_CVERIFY_OPTIONAL_NO_CA))
        verify |= SSL_VERIFY_PEER;
    if (!c->store) {
        if (ssl_methods.SSL_CTX_set_default_verify_paths(c->ctx)) {
            c->store = ssl_methods.SSL_CTX_get_cert_store(c->ctx);
            crypto_methods.X509_STORE_set_flags(c->store, 0);
        }
        else {
            /* XXX: See if this is fatal */
        }
    }

    ssl_methods.SSL_set_verify(ssl_, verify, SSL_callback_SSL_verify);
}

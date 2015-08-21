#include "utssl.h"

extern ssl_dynamic_methods ssl_methods;
extern crypto_dynamic_methods crypto_methods;

static int ssl_X509_STORE_lookup(X509_STORE *store, int yype,
                                 X509_NAME *name, X509_OBJECT *obj)
{
    X509_STORE_CTX ctx;
    int rc;

    crypto_methods.X509_STORE_CTX_init(&ctx, store, NULL, NULL);
    rc = crypto_methods.X509_STORE_get_by_subject(&ctx, yype, name, obj);
    crypto_methods.X509_STORE_CTX_cleanup(&ctx);
    return rc;
}


static int ssl_verify_CRL(int ok, X509_STORE_CTX *ctx, tcn_ssl_conn_t *con)
{
    X509_OBJECT obj;
    X509_NAME *subject, *issuer;
    X509 *cert;
    X509_CRL *crl;
    EVP_PKEY *pubkey;
    int i, n, rc;

    /*
     * Determine certificate ingredients in advance
     */
    cert    = crypto_methods.X509_STORE_CTX_get_current_cert(ctx);
    subject = crypto_methods.X509_get_subject_name(cert);
    issuer  = crypto_methods.X509_get_issuer_name(cert);

    /*
     * OpenSSL provides the general mechanism to deal with CRLs but does not
     * use them automatically when verifying certificates, so we do it
     * explicitly here. We will check the CRL for the currently checked
     * certificate, if there is such a CRL in the store.
     *
     * We come through this procedure for each certificate in the certificate
     * chain, starting with the root-CA's certificate. At each step we've to
     * both verify the signature on the CRL (to make sure it's a valid CRL)
     * and it's revocation list (to make sure the current certificate isn't
     * revoked).  But because to check the signature on the CRL we need the
     * public key of the issuing CA certificate (which was already processed
     * one round before), we've a little problem. But we can both solve it and
     * at the same time optimize the processing by using the following
     * verification scheme (idea and code snippets borrowed from the GLOBUS
     * project):
     *
     * 1. We'll check the signature of a CRL in each step when we find a CRL
     *    through the _subject_ name of the current certificate. This CRL
     *    itself will be needed the first time in the next round, of course.
     *    But we do the signature processing one round before this where the
     *    public key of the CA is available.
     *
     * 2. We'll check the revocation list of a CRL in each step when
     *    we find a CRL through the _issuer_ name of the current certificate.
     *    This CRLs signature was then already verified one round before.
     *
     * This verification scheme allows a CA to revoke its own certificate as
     * well, of course.
     */

    /*
     * Try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity.
     */
    memset((char *)&obj, 0, sizeof(obj));
    rc = ssl_X509_STORE_lookup(con->ctx->crl,
                               X509_LU_CRL, subject, &obj);
    crl = obj.data.crl;

    if ((rc > 0) && crl) {
        /*
         * Log information about CRL
         * (A little bit complicated because of ASN.1 and BIOs...)
         */
        /*
         * Verify the signature on this CRL
         */
        pubkey = crypto_methods.X509_get_pubkey(cert);
        rc = crypto_methods.X509_CRL_verify(crl, pubkey);
        /* Only refcounted in OpenSSL */
        if (pubkey)
            crypto_methods.EVP_PKEY_free(pubkey);
        if (rc <= 0) {
            /* TODO: Log Invalid signature on CRL */
            crypto_methods.X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            crypto_methods.X509_OBJECT_free_contents(&obj);
            return 0;
        }

        /*
         * Check date of CRL to make sure it's not expired
         */
        i = crypto_methods.X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));

        if (i == 0) {
            /* TODO: Log Found CRL has invalid nextUpdate field */

            crypto_methods.X509_STORE_CTX_set_error(ctx,
                                     X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            crypto_methods.X509_OBJECT_free_contents(&obj);
            return 0;
        }

        if (i < 0) {
            /* TODO: Log Found CRL is expired */
            crypto_methods.X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            crypto_methods.X509_OBJECT_free_contents(&obj);

            return 0;
        }

        crypto_methods.X509_OBJECT_free_contents(&obj);
    }

    /*
     * Try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation.
     */
    memset((char *)&obj, 0, sizeof(obj));
    rc = ssl_X509_STORE_lookup(con->ctx->crl,
                               X509_LU_CRL, issuer, &obj);

    crl = obj.data.crl;
    if ((rc > 0) && crl) {
        /*
         * Check if the current certificate is revoked by this CRL
         */
        n = crypto_methods.sk_num(X509_CRL_get_REVOKED(crl));

        for (i = 0; i < n; i++) {
            X509_REVOKED *revoked =
                crypto_methods.sk_value(X509_CRL_get_REVOKED(crl), i);

            ASN1_INTEGER *sn = revoked->serialNumber;

            if (!crypto_methods.ASN1_INTEGER_cmp(sn, crypto_methods.X509_get_serialNumber(cert))) {
                crypto_methods.X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
                crypto_methods.X509_OBJECT_free_contents(&obj);

                return 0;
            }
        }

        crypto_methods.X509_OBJECT_free_contents(&obj);
    }

    return ok;
}

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
     * Additionally perform CRL-based revocation checks
     */
    if (ok && con->ctx->crl && !skip_crl) {
        if (!(ok = ssl_verify_CRL(ok, ctx, con))) {
            errnum = crypto_methods.X509_STORE_CTX_get_error(ctx);
            /* TODO: Log something */
        }
    }
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


UT_OPENSSL(void, setSSLContextVerify)(JNIEnv *e, jobject o, jlong ctx,
                                                jint level, jint depth)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int verify = SSL_VERIFY_NONE;

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
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
    //TODO: fix this
    ssl_methods.SSL_CTX_set_verify(c->ctx, verify, SSL_callback_SSL_verify);
}



UT_OPENSSL(void, setVerify)(JNIEnv *e, jobject o, jlong ssl, jint level, jint depth)
{
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
    TCN_ASSERT(ctx != 0);
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

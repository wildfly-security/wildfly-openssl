/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License") you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.openssl;

import java.nio.ByteBuffer;

/**
 * Class that contains all static native methods to interact with OpenSSL
 */
public class SSLImpl extends SSL {

    public SSLImpl() {
    }

    static native void initialize0(String libCryptoPath, String libSslPath);

    protected void initialize(String libCryptoPath, String libSslPath) {
        SSLImpl.initialize0(libCryptoPath, libSslPath);
    }

    /* Return OpenSSL version number as a string */
    static native String version0();

    protected String version() {
        return SSLImpl.version0();
    }

    /* Return OpenSSL version number */
    static native long versionNumber0();

    @Override
    protected long versionNumber() {
        return SSLImpl.versionNumber0();
    }

    /**
     * Return true if all the requested SSL_OP_* are supported by OpenSSL.
     * <p>
     * <i>Note that for versions of tcstatic native &lt; 1.1.25, this method will
     * return <code>true</code> if and only if <code>op</code>=
     * {@link #SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION} and tcstatic native
     * supports that flag.</i>
     *
     * @param op Bitwise-OR of all SSL_OP_* to test.
     * @return true if all SSL_OP_* are supported by OpenSSL library.
     */
    static native boolean hasOp0(int op);

    protected boolean hasOp(int op) {
        return SSLImpl.hasOp0(op);
    }

    /**
     * SSL_new
     *
     * @param ctx    Server or Client context to use.
     * @param server if true configure SSL instance to use accept handshake routines
     *               if false configure SSL instance to use connect handshake routines
     * @return pointer to SSL instance (SSL *)
     */
    static native long newSSL0(long ctx, boolean server);

    protected long newSSL(long ctx, boolean server) {
        return SSLImpl.newSSL0(ctx, server);
    }

    /**
     * BIO_ctrl_pending.
     *
     * @param bio BIO pointer (BIO *)
     */
    static native int pendingWrittenBytesInBIO0(long bio);

    protected int pendingWrittenBytesInBIO(long bio) {
        return SSLImpl.pendingWrittenBytesInBIO0(bio);
    }

    /**
     * SSL_pending.
     *
     * @param ssl SSL pointer (SSL *)
     */
    static native int pendingReadableBytesInSSL0(long ssl);

    protected int pendingReadableBytesInSSL(long ssl) {
        return SSLImpl.pendingReadableBytesInSSL0(ssl);
    }

    /**
     * BIO_write.
     *
     * @param bio
     * @param wbuf
     * @param wlen
     */
    static native int writeToBIO0(long bio, long wbuf, int wlen);

    protected int writeToBIO(long bio, long wbuf, int wlen) {
        return SSLImpl.writeToBIO0(bio, wbuf, wlen);
    }

    /**
     * BIO_read.
     *
     * @param bio
     * @param rbuf
     * @param rlen
     */
    static native int readFromBIO0(long bio, long rbuf, int rlen);

    protected int readFromBIO(long bio, long rbuf, int rlen) {
        return SSLImpl.readFromBIO0(bio, rbuf, rlen);
    }

    /**
     * SSL_write.
     *
     * @param ssl  the SSL instance (SSL *)
     * @param wbuf
     * @param wlen
     */
    static native int writeToSSL0(long ssl, long wbuf, int wlen);

    protected int writeToSSL(long ssl, long wbuf, int wlen) {
        return SSLImpl.writeToSSL0(ssl, wbuf, wlen);
    }

    /**
     * SSL_read
     *
     * @param ssl  the SSL instance (SSL *)
     * @param rbuf
     * @param rlen
     */
    static native int readFromSSL0(long ssl, long rbuf, int rlen);

    protected int readFromSSL(long ssl, long rbuf, int rlen) {
        return SSLImpl.readFromSSL0(ssl, rbuf, rlen);
    }

    /**
     * SSL_get_shutdown
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native int getShutdown0(long ssl);

    protected int getShutdown(long ssl) {
        return SSLImpl.getShutdown0(ssl);
    }

    /**
     * SSL_free
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native void freeSSL0(long ssl);

    protected void freeSSL(long ssl) {
        SSLImpl.freeSSL0(ssl);
    }

    /**
     * Wire up internal and network BIOs for the given SSL instance.
     * <p>
     * <b>Warning: you must explicitly free this resource by calling freeBIO</b>
     * <p>
     * While the SSL's internal/application data BIO will be freed when freeSSL is called on
     * the provided SSL instance, you must call freeBIO on the returned network BIO.
     *
     * @param ssl the SSL instance (SSL *)
     * @return pointer to the Network BIO (BIO *)
     */
    static native long makeNetworkBIO0(long ssl);

    protected long makeNetworkBIO(long ssl) {
        return SSLImpl.makeNetworkBIO0(ssl);
    }

    /**
     * BIO_free
     *
     * @param bio
     */
    static native void freeBIO0(long bio);

    protected void freeBIO(long bio) {
        SSLImpl.freeBIO0(bio);
    }

    /**
     * SSL_shutdown
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native int shutdownSSL0(long ssl);

    protected int shutdownSSL(long ssl) {
        return SSLImpl.shutdownSSL0(ssl);
    }

    /**
     * Get the error number representing the last error OpenSSL encountered on
     * this thread.
     */
    static native int getLastErrorNumber0();

    protected int getLastErrorNumber() {
        return SSLImpl.getLastErrorNumber0();
    }

    /**
     * SSL_get_cipher.
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native String getCipherForSSL0(long ssl);

    protected String getCipherForSSL(long ssl) {
        return SSLImpl.getCipherForSSL0(ssl);
    }

    /**
     * SSL_get_version
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native String getVersion0(long ssl);

    protected String getVersion(long ssl) {
        return SSLImpl.getVersion0(ssl);
    }

    /**
     * SSL_do_handshake
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native int doHandshake0(long ssl);

    protected int doHandshake(long ssl) {
        return SSLImpl.doHandshake0(ssl);
    }

    static native void saveServerCipher0(long ssl, int serverCipher);

    protected void saveServerCipher(long ssl, int serverCipher) {
        SSLImpl.saveServerCipher0(ssl, serverCipher);
    }
    static native int getSSLError0(long ssl, int code);

    protected int getSSLError(long ssl, int code) {
        return SSLImpl.getSSLError0(ssl, code);
    }

    /**
     * SSL_renegotiate
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native int renegotiate0(long ssl);

    protected int renegotiate(long ssl) {
        return SSLImpl.renegotiate0(ssl);
    }

    /**
     * SSL_in_init.
     *
     * @param SSL
     */
    static native int isInInit0(long SSL);

    protected int isInInit(long SSL) {
        return SSLImpl.isInInit0(SSL);
    }

    /**
     * SSL_get0_alpn_selected
     *
     * @param ssl the SSL instance (SSL *)
     */
    static native String getAlpnSelected0(long ssl);

    protected String getAlpnSelected(long ssl) {
        return SSLImpl.getAlpnSelected0(ssl);
    }

    /**
     * enables ALPN on the server side
     */
    static native void enableAlpn0(long ssl);

    protected void enableAlpn(long ssl) {
        SSLImpl.enableAlpn0(ssl);
    }

    static native boolean isAlpnSupported0();

    protected boolean isAlpnSupported() {
        return isAlpnSupported0();
    }

    /**
     * Get the peer certificate chain or {@code null} if non was send.
     */
    static native byte[][] getPeerCertChain0(long ssl);

    protected byte[][] getPeerCertChain(long ssl) {
        return SSLImpl.getPeerCertChain0(ssl);
    }

    /**
     * Get the peer certificate or {@code null} if non was send.
     */
    static native byte[] getPeerCertificate0(long ssl);

    protected byte[] getPeerCertificate(long ssl) {
        return SSLImpl.getPeerCertificate0(ssl);
    }

    /*
     * Get the error number representing for the given {@code errorNumber}.
     */
    static native String getErrorString0(long errorNumber);

    protected String getErrorString(long errorNumber) {
        return SSLImpl.getErrorString0(errorNumber);
    }

    /**
     * SSL_get_time
     *
     * @param ssl the SSL instance (SSL *)
     * @return returns the time at which the session ssl was established. The time is given in seconds since the Epoch
     */
    static native long getTime0(long ssl);

    protected long getTime(long ssl) {
        return SSLImpl.getTime0(ssl);
    }

    /**
     * Set Type of Client Certificate verification and Maximum depth of CA Certificates
     * in Client Certificate verification.
     * <br />
     * This directive sets the Certificate verification level for the Client
     * Authentication. Notice that this directive can be used both in per-server
     * and per-directory context. In per-server context it applies to the client
     * authentication process used in the standard SSL handshake when a connection
     * is established. In per-directory context it forces a SSL renegotiation with
     * the reconfigured client verification level after the HTTP request was read
     * but before the HTTP response is sent.
     * <br />
     * The following levels are available for level:
     * <pre>
     * SSL_CVERIFY_NONE           - No client Certificate is required at all
     * SSL_CVERIFY_OPTIONAL       - The client may present a valid Certificate
     * SSL_CVERIFY_REQUIRE        - The client has to present a valid Certificate
     * SSL_CVERIFY_OPTIONAL_NO_CA - The client may present a valid Certificate
     *                              but it need not to be (successfully) verifiable
     * </pre>
     * <br />
     * The depth actually is the maximum number of intermediate certificate issuers,
     * i.e. the number of CA certificates which are max allowed to be followed while
     * verifying the client certificate. A depth of 0 means that self-signed client
     * certificates are accepted only, the default depth of 1 means the client
     * certificate can be self-signed or has to be signed by a CA which is directly
     * known to the server (i.e. the CA's certificate is under
     * {@code setCACertificatePath}, etc.
     *
     * @param ssl   the SSL instance (SSL *)
     * @param level Type of Client Certificate verification.
     * @param depth Maximum depth of CA Certificates in Client Certificate
     *              verification.
     */
    static native void setSSLVerify0(long ssl, int level, int depth);

    protected void setSSLVerify(long ssl, int level, int depth) {
        SSLImpl.setSSLVerify0(ssl, level, depth);
    }

    /**
     * Set OpenSSL Option.
     *
     * @param ssl     the SSL instance (SSL *)
     * @param options See SSL.SSL_OP_* for option flags.
     */
    static native void setOptions0(long ssl, long options);

    protected void setOptions(long ssl, long options) {
        SSLImpl.setOptions0(ssl, options);
    }

    /**
     * Get OpenSSL Option.
     *
     * @param ssl the SSL instance (SSL *)
     * @return options  See SSL.SSL_OP_* for option flags.
     */
    static native long getOptions0(long ssl);

    protected long getOptions(long ssl) {
        return SSLImpl.getOptions0(ssl);
    }

    /**
     * Returns all Returns the cipher suites that are available for negotiation in an SSL handshake.
     *
     * @param ssl the SSL instance (SSL *)
     * @return ciphers
     */
    static native String[] getCiphers0(long ssl);

    protected String[] getCiphers(long ssl) {
        return SSLImpl.getCiphers0(ssl);
    }

    @Override
    protected boolean setCipherSuites(long ssl, String ciphers) throws Exception {
        return setCipherSuites0(ssl, ciphers);
    }

    @Override
    protected boolean setCipherSuitesTLS13(long ssl, String ciphers) throws Exception {
        return setCipherSuitesTLS130(ssl, ciphers);
    }

    static native boolean setServerNameIndication0(long ssl, String hostName);

    @Override
    protected boolean setServerNameIndication(long ssl, String hostName) {
        return setServerNameIndication0(ssl, hostName);
    }

    /**
     * Returns the pointer reference to the SSL session.
     *
     * @param ssl the SSL instance (SSL *)
     *
     * @return the pointer reference to the SSL session
     */
    static native long getSession0(long ssl);

    @Override
    protected long getSession(long ssl) {
        return SSLImpl.getSession0(ssl);
    }

    static native void setSession0(long ssl, long session);

    @Override
    protected void setSession(long ssl, final long session) {
        SSLImpl.setSession0(ssl, session);
    }

    /**
     * Returns the cipher suites available for negotiation in SSL handshake.
     * <br />
     * This complex directive uses a colon-separated cipher-spec string consisting
     * of OpenSSL cipher specifications to configure the Cipher Suite the client
     * is permitted to negotiate in the SSL handshake phase. Notice that this
     * directive can be used both in per-server and per-directory context.
     * In per-server context it applies to the standard SSL handshake when a
     * connection is established. In per-directory context it forces a SSL
     * renegotiation with the reconfigured Cipher Suite after the HTTP request
     * was read but before the HTTP response is sent.
     *
     * @param ssl     the SSL instance (SSL *)
     * @param ciphers an SSL cipher specification
     */
    static native boolean setCipherSuites0(long ssl, String ciphers) throws Exception;

    /**
     * Sets the cipher suites available for negotiation in the SSL handshake.
     * <br />
     * This is a simple colon (":") separated list of TLSv1.3 ciphersuite names in order of preference.
     *
     * @param ssl     the SSL instance (SSL *)
     * @param ciphers an SSL cipher specification
     */
    static native boolean setCipherSuitesTLS130(long ssl, String ciphers) throws Exception;


    /**
     * Returns the ID of the session as byte array representation.
     *
     * @param ssl the SSL instance (SSL *)
     * @return the session as byte array representation obtained via SSL_SESSION_get_id.
     */
    static native byte[] getSessionId0(long ssl);

    protected byte[] getSessionId(long ssl) {
        return SSLImpl.getSessionId0(ssl);
    }

    static native long bufferAddress0(ByteBuffer buffer);

    protected long bufferAddress(ByteBuffer buffer) {
        return SSLImpl.bufferAddress0(buffer);
    }

    @Override
    protected long makeSSLContext(int protocol, int mode) throws Exception {
        return makeSSLContext0(protocol, mode);
    }


    /**
     * Create a new SSL context.
     *
     * @param protocol The SSL protocol to use. It can be any combination of
     *                 the following:
     *                 <PRE>
     *                 {@link SSLImpl#SSL_PROTOCOL_SSLV2}
     *                 {@link SSLImpl#SSL_PROTOCOL_SSLV3}
     *                 {@link SSLImpl#SSL_PROTOCOL_TLSV1}
     *                 {@link SSLImpl#SSL_PROTOCOL_TLSV1_1}
     *                 {@link SSLImpl#SSL_PROTOCOL_TLSV1_2}
     *                 {@link SSLImpl#SSL_PROTOCOL_TLSV1_3}
     *                 {@link SSLImpl#SSL_PROTOCOL_ALL} ( == all TLS versions, no SSL)
     *                 </PRE>
     * @param mode     SSL mode to use
     *                 <PRE>
     *                 SSL_MODE_CLIENT
     *                 SSL_MODE_SERVER
     *                 SSL_MODE_COMBINED
     *                 </PRE>
     * @return The Java representation of a pointer to the newly created SSL
     * Context
     * @throws Exception If the SSL Context could not be created
     */
    static native long makeSSLContext0(int protocol, int mode) throws Exception;

    /**
     * Free the resources used by the Context
     *
     * @param ctx Server or Client context to free.
     * @return APR Status code.
     */
    static native int freeSSLContext0(long ctx);

    protected int freeSSLContext(long ctx) {
        return SSLImpl.freeSSLContext0(ctx);
    }

    /**
     * Set OpenSSL Option.
     *
     * @param ctx     Server or Client context to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    static native void setSSLContextOptions0(long ctx, long options);

    protected void setSSLContextOptions(long ctx, long options) {
        SSLImpl.setSSLContextOptions0(ctx, options);
    }

    /**
     * Clears OpenSSL Options.
     *
     * @param ctx     Server or Client context to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    static native void clearSSLContextOptions0(long ctx, long options);

    protected void clearSSLContextOptions(long ctx, long options) {
        SSLImpl.clearSSLContextOptions0(ctx, options);
    }

    /**
     * Set OpenSSL Option.
     *
     * @param ssl     Server or Client SSL to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    static native void setSSLOptions0(long ssl, long options);

    protected void setSSLOptions(long ssl, long options) {
        SSLImpl.setSSLOptions0(ssl, options);
    }

    /**
     * Clears OpenSSL Options.
     *
     * @param ssl     Server or Client SSL to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    static native void clearSSLOptions0(long ssl, long options);

    protected void clearSSLOptions(long ssl, long options) {
        SSLImpl.clearSSLOptions0(ssl, options);
    }

    @Override
    protected boolean setCipherSuite(long ctx, String ciphers) throws Exception {
        return setCipherSuite0(ctx, ciphers);
    }

    @Override
    protected boolean setCipherSuiteTLS13(long ctx, String ciphers) throws Exception {
        return setCipherSuiteTLS130(ctx, ciphers);
    }

    @Override
    protected boolean setCARevocation(long ctx, String file, String path) throws Exception {
        return setCARevocation0(ctx, file, path);
    }

    @Override
    protected boolean setCertificate(long ctx, byte[] cert, byte[][] encodedIntermediaries, byte[] key, int idx) throws Exception {
        return setCertificate0(ctx, cert, encodedIntermediaries, key, idx);
    }

    /**
     * Cipher Suite available for negotiation in SSL handshake.
     * <br>
     * This complex directive uses a colon-separated cipher-spec string consisting
     * of OpenSSL cipher specifications to configure the Cipher Suite the client
     * is permitted to negotiate in the SSL handshake phase. Notice that this
     * directive can be used both in per-server and per-directory context.
     * In per-server context it applies to the standard SSL handshake when a
     * connection is established. In per-directory context it forces a SSL
     * renegotiation with the reconfigured Cipher Suite after the HTTP request
     * was read but before the HTTP response is sent.
     *
     * @param ctx     Server or Client context to use.
     * @param ciphers An SSL cipher specification.
     */
    static native boolean setCipherSuite0(long ctx, String ciphers) throws Exception;

    /**
     * Sets the cipher suites available for negotiation in the SSL handshake.
     * <br />
     * This is a simple colon (":") separated list of TLSv1.3 ciphersuite names in order of preference.
     *
     * @param ctx     Server or Client context to use.
     * @param ciphers an SSL cipher specification
     */
    static native boolean setCipherSuiteTLS130(long ctx, String ciphers) throws Exception;

    /**
     * Set File of concatenated PEM-encoded CA CRLs or
     * directory of PEM-encoded CA Certificates for Client Auth
     * <br>
     * This directive sets the all-in-one file where you can assemble the
     * Certificate Revocation Lists (CRL) of Certification Authorities (CA)
     * whose clients you deal with. These are used for Client Authentication.
     * Such a file is simply the concatenation of the various PEM-encoded CRL
     * files, in order of preference.
     * <br>
     * The files in this directory have to be PEM-encoded and are accessed through
     * hash filenames. So usually you can't just place the Certificate files there:
     * you also have to create symbolic links named hash-value.N. And you should
     * always make sure this directory contains the appropriate symbolic links.
     * Use the Makefile which comes with mod_ssl to accomplish this task.
     *
     * @param ctx  Server or Client context to use.
     * @param file File of concatenated PEM-encoded CA CRLs for Client Auth.
     * @param path Directory of PEM-encoded CA Certificates for Client Auth.
     */
    static native boolean setCARevocation0(long ctx, String file,
                                    String path) throws Exception;

    /**
     * Set Certificate
     * <br>
     * Point setCertificateFile at a PEM encoded certificate.  If
     * the certificate is encrypted, then you will be prompted for a
     * pass phrase.  Note that a kill -HUP will prompt again. A test
     * certificate can be generated with `make certificate' under
     * built time. Keep in mind that if you've both a RSA and a DSA
     * certificate you can configure both in parallel (to also allow
     * the use of DSA ciphers, etc.)
     * <br>
     * If the key is not combined with the certificate, use key param
     * to point at the key file.  Keep in mind that if
     * you've both a RSA and a DSA private key you can configure
     * both in parallel (to also allow the use of DSA ciphers, etc.)
     *  @param ctx  Server or Client context to use.
     * @param cert Certificate file.
     * @param encodedIntermediaries
     * @param key  Private Key file to use if not in cert.
     * @param idx  Certificate index SSL_AIDX_RSA or SSL_AIDX_DSA.
     */
    static native boolean setCertificate0(long ctx, byte[] cert,
                                          byte[][] encodedIntermediaries, byte[] key,
                                          int idx) throws Exception;

    /**
     * Set the size of the internal session cache.
     * http://www.openssl.org/docs/ssl/SSL_CTX_sess_set_cache_size.html
     */
    static native long setSessionCacheSize0(long ctx, long size);

    protected long setSessionCacheSize(long ctx, long size) {
        return SSLImpl.setSessionCacheSize0(ctx, size);
    }

    /**
     * Get the size of the internal session cache.
     * http://www.openssl.org/docs/ssl/SSL_CTX_sess_get_cache_size.html
     */
    static native long getSessionCacheSize0(long ctx);

    protected long getSessionCacheSize(long ctx) {
        return SSLImpl.getSessionCacheSize0(ctx);
    }

    /**
     * Set the timeout for the internal session cache in seconds.
     * http://www.openssl.org/docs/ssl/SSL_CTX_set_timeout.html
     */
    static native long setSessionCacheTimeout0(long ctx, long timeoutSeconds);

    protected long setSessionCacheTimeout(long ctx, long timeoutSeconds) {
        return SSLImpl.setSessionCacheTimeout0(ctx, timeoutSeconds);
    }

    /**
     * Get the timeout for the internal session cache in seconds.
     * http://www.openssl.org/docs/ssl/SSL_CTX_set_timeout.html
     */
    static native long getSessionCacheTimeout0(long ctx);

    protected long getSessionCacheTimeout(long ctx) {
        return SSLImpl.getSessionCacheTimeout0(ctx);
    }

    /**
     * Set the mode of the internal session cache and return the previous used mode.
     */
    static native long setSessionCacheMode0(long ctx, long mode);

    protected long setSessionCacheMode(long ctx, long mode) {
        return SSLImpl.setSessionCacheMode0(ctx, mode);
    }

    /**
     * Get the mode of the current used internal session cache.
     */
    static native long getSessionCacheMode0(long ctx);

    protected long getSessionCacheMode(long ctx) {
        return SSLImpl.getSessionCacheMode0(ctx);
    }

    /**
     * Session resumption statistics methods.
     * http://www.openssl.org/docs/ssl/SSL_CTX_sess_number.html
     */
    static native long sessionAccept0(long ctx);

    protected long sessionAccept(long ctx) {
        return SSLImpl.sessionAccept0(ctx);
    }

    static native long sessionAcceptGood0(long ctx);

    protected long sessionAcceptGood(long ctx) {
        return SSLImpl.sessionAcceptGood0(ctx);
    }

    static native long sessionAcceptRenegotiate0(long ctx);

    protected long sessionAcceptRenegotiate(long ctx) {
        return SSLImpl.sessionAcceptRenegotiate0(ctx);
    }

    static native long sessionCacheFull0(long ctx);

    protected long sessionCacheFull(long ctx) {
        return SSLImpl.sessionCacheFull0(ctx);
    }

    static native long sessionCbHits0(long ctx);

    protected long sessionCbHits(long ctx) {
        return SSLImpl.sessionCbHits0(ctx);
    }

    static native long sessionConnect0(long ctx);

    protected long sessionConnect(long ctx) {
        return SSLImpl.sessionConnect0(ctx);
    }

    static native long sessionConnectGood0(long ctx);

    protected long sessionConnectGood(long ctx) {
        return SSLImpl.sessionConnectGood0(ctx);
    }

    static native long sessionConnectRenegotiate0(long ctx);

    protected long sessionConnectRenegotiate(long ctx) {
        return SSLImpl.sessionConnectRenegotiate0(ctx);
    }

    static native long sessionHits0(long ctx);

    protected long sessionHits(long ctx) {
        return SSLImpl.sessionHits0(ctx);
    }

    static native long sessionMisses0(long ctx);

    protected long sessionMisses(long ctx) {
        return SSLImpl.sessionMisses0(ctx);
    }

    static native long sessionNumber0(long ctx);

    protected long sessionNumber(long ctx) {
        return SSLImpl.sessionNumber0(ctx);
    }

    static native long sessionTimeouts0(long ctx);

    protected long sessionTimeouts(long ctx) {
        return SSLImpl.sessionTimeouts0(ctx);
    }

    /**
     * Set TLS session keys. This allows us to share keys across TFEs.
     */
    static native void setSessionTicketKeys0(long ctx, byte[] keys);

    protected void setSessionTicketKeys(long ctx, byte[] keys) {
        SSLImpl.setSessionTicketKeys0(ctx, keys);
    }

    /**
     * invalidates the current SSL session
     */
    static native void invalidateSession0(long ctx);

    protected void invalidateSession(long ctx) {
        SSLImpl.invalidateSession0(ctx);
    }

    static native void registerSessionContext0(long context, OpenSSLSessionContext openSSLSessionContext);

    protected void registerSessionContext(long context, OpenSSLSessionContext openSSLSessionContext) {
        SSLImpl.registerSessionContext0(context, openSSLSessionContext);
    }

    /**
     * Allow to hook {@link CertificateVerifier} into the handshake processing.
     * This will call {@code SSL_CTX_set_cert_verify_callback} and so replace the default verification
     * callback used by openssl
     *
     * @param ctx      Server or Client context to use.
     * @param verifier the verifier to call during handshake.
     */
    static native void setCertVerifyCallback0(long ctx, CertificateVerifier verifier);

    protected void setCertVerifyCallback(long ctx, CertificateVerifier verifier) {
        SSLImpl.setCertVerifyCallback0(ctx, verifier);
    }

    /**
     * Set application layer protocol for application layer protocol negotiation extension.
     * <p>
     * This should only be called by the client.
     *
     * @param ssl        SSL Engine to use
     * @param alpnProtos protocols in priority order
     */
    static native void setAlpnProtos0(long ssl, String[] alpnProtos);

    protected void setAlpnProtos(long ssl, String[] alpnProtos) {
        SSLImpl.setAlpnProtos0(ssl, alpnProtos);
    }

    /**
     * Sets the server ALPN callback for a spcific engine
     *
     * @param ssl      The SSL engine
     * @param callback the callbackto use
     */
    static native void setServerALPNCallback0(long ssl, ServerALPNCallback callback);

    protected void setServerALPNCallback(long ssl, ServerALPNCallback callback) {
        SSLImpl.setServerALPNCallback0(ssl, callback);
    }

    /**
     * Set the context within which session be reused (server side only)
     * http://www.openssl.org/docs/ssl/SSL_CTX_set_session_id_context.html
     *
     * @param ctx    Server context to use.
     * @param sidCtx can be any kind of binary data, it is therefore possible to use e.g. the name
     *               of the application and/or the hostname and/or service name
     * @return {@code true} if success, {@code false} otherwise.
     */
    static native boolean setSessionIdContext0(long ctx, byte[] sidCtx);

    protected boolean setSessionIdContext(long ctx, byte[] sidCtx) {
        return SSLImpl.setSessionIdContext0(ctx, sidCtx);
    }

    static native void setMinProtoVersion0(long ssl, int version);

    protected void setMinProtoVersion(long ssl, int version) {
        SSLImpl.setMinProtoVersion0(ssl, version);
    }

    static native void setMaxProtoVersion0(long ssl, int version);

    protected void setMaxProtoVersion(long ssl, int version) {
        SSLImpl.setMaxProtoVersion0(ssl, version);
    }

    static native int getMinProtoVersion0(long ssl);

    protected int getMinProtoVersion(long ssl) {
        return SSLImpl.getMinProtoVersion0(ssl);
    }

    static native int getMaxProtoVersion0(long ssl);

    protected int getMaxProtoVersion(long ssl) {
        return SSLImpl.getMaxProtoVersion0(ssl);
    }

    static native boolean getSSLSessionReused0(long ssl);

    protected boolean getSSLSessionReused(long ssl) {
        return SSLImpl.getSSLSessionReused0(ssl);
    }

}

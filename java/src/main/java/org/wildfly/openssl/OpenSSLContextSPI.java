/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
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


import org.wildfly.openssl.util.SNIUtil;

import static org.wildfly.openssl.OpenSSLEngine.isTLS13Supported;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class OpenSSLContextSPI extends SSLContextSpi {

    private static final Logger LOG = Logger.getLogger(OpenSSLContextSPI.class.getName());

    public static final int DEFAULT_SESSION_CACHE_SIZE = 1000;

    private static final String BEGIN_RSA_CERT = "-----BEGIN RSA PRIVATE KEY-----\n";

    private static final String END_RSA_CERT = "\n-----END RSA PRIVATE KEY-----";

    private static final String BEGIN_DSA_CERT = "-----BEGIN DSA PRIVATE KEY-----\n";

    private static final String END_DSA_CERT = "\n-----END DSA PRIVATE KEY-----";

    private static final String SSL_KEYSTORE_DEFAULT_ALIAS = System.getProperty("org.wildfly.sni.keystore.default.alias");

    private static final String[] ALGORITHMS = {"RSA", "DSA"};

    private OpenSSLServerSessionContext serverSessionContext;
    private OpenSSLClientSessionContext clientSessionContext;

    private static volatile String[] allAvailableCiphers;

    private static final String TLS13_CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";

    protected final long serverCtx; // the default SSL server ctx
    protected final long clientCtx; // the default SSL client ctx
    protected Set<Long> allServerCtxs; // All initialized SSL server ctxs
    protected Set<Long> allClientCtxs; // All initialized SSL client ctxs
    final int supportedCiphers;


    private volatile String[] ciphers;

    static final CertificateFactory X509_CERT_FACTORY;
    private boolean initialized = false;

    static {
        try {
            X509_CERT_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String[] getAvailableCipherSuites() {
        if(allAvailableCiphers == null) {
            synchronized (OpenSSLContextSPI.class) {
                if(allAvailableCiphers == null) {

                    final Set<String> availableCipherSuites = new LinkedHashSet<>(128);
                    boolean tls13Supported = isTLS13Supported();
                    try {
                        final long sslCtx = SSL.getInstance().makeSSLContext(SSL.SSL_PROTOCOL_ALL, SSL.SSL_MODE_SERVER);
                        try {
                            SSL.getInstance().setSSLContextOptions(sslCtx, SSL.SSL_OP_ALL);
                            if (tls13Supported) {
                                SSL.getInstance().setCipherSuiteTLS13(sslCtx, TLS13_CIPHERS);
                            }
                            SSL.getInstance().setCipherSuite(sslCtx, "ALL");
                            final long ssl = SSL.getInstance().newSSL(sslCtx, true);
                            try {
                                for (String c : SSL.getInstance().getCiphers(ssl)) {
                                    // Filter out bad input.
                                    if (c == null || c.length() == 0 || availableCipherSuites.contains(c)) {
                                        continue;
                                    }
                                    availableCipherSuites.add(CipherSuiteConverter.toJava(c, "TLS"));
                                }
                            } finally {
                                SSL.getInstance().freeSSL(ssl);
                            }
                        } finally {
                            SSL.getInstance().freeSSLContext(sslCtx);
                        }
                    } catch (Exception e) {
                        LOG.log(Level.WARNING, Messages.MESSAGES.failedToInitializeCiphers(), e);
                    }
                    allAvailableCiphers = availableCipherSuites.toArray(new String[availableCipherSuites.size()]);
                }
            }
        }
        return allAvailableCiphers;
    }

    OpenSSLContextSPI(final int value) throws SSLException {
        this.supportedCiphers = value;
        SSL.init();
        serverCtx = makeSSLContext();
        clientCtx = makeSSLContext();
        allServerCtxs = new HashSet<>(Arrays.asList(serverCtx)); // include the only existing context, this might become bigger during initialization
        allClientCtxs = new HashSet<>(Arrays.asList(clientCtx)); // include the only existing context, this might become bigger during initialization
    }

    private long makeSSLContext() throws RuntimeException {
        final long sslCtx;

        try {
            // Create SSL Context
            try {
                sslCtx = SSL.getInstance().makeSSLContext(this.supportedCiphers, SSL.SSL_MODE_COMBINED);
            } catch (Exception e) {
                // If the sslEngine is disabled on the AprLifecycleListener
                // there will be an Exception here but there is no way to check
                // the AprLifecycleListener settings from here
                throw new SSLException(Messages.MESSAGES.failedToMakeSslContext(), e);
            }
            try {
                //disable unsafe renegotiation
                SSL.getInstance().clearSSLContextOptions(sslCtx, SSL.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            // Disable compression
            SSL.getInstance().setSSLContextOptions(sslCtx, SSL.SSL_OP_NO_COMPRESSION);

            // Disable TLS Session Tickets (RFC4507) to protect perfect forward secrecy
            SSL.getInstance().setSSLContextOptions(sslCtx, SSL.SSL_OP_NO_TICKET);
        } catch (Exception e) {
            throw new RuntimeException(Messages.MESSAGES.failedToInitializeSslContext(), e);
        }
        return sslCtx;
    }

    /**
     * Setup the SSL_CTX
     *
     * @param kms Must contain a KeyManager of the type
     *            {@code OpenSSLKeyManager}
     * @param tms
     */
    private synchronized void init(KeyManager[] kms, TrustManager[] tms) throws KeyManagementException {
        if (this.initialized) {
            LOG.warning(Messages.MESSAGES.ignoringSecondInit());
            return;
        }

        this.allServerCtxs = this.makeAllCtxs(kms, tms, serverCtx);
        this.serverSessionContext = new OpenSSLServerSessionContext(serverCtx);
        this.serverSessionContext.setSessionIdContext("test".getBytes(StandardCharsets.US_ASCII));

        this.allClientCtxs = this.makeAllCtxs(kms, tms, clientCtx);
        this.clientSessionContext = new OpenSSLClientSessionContext(serverCtx);

        this.initialized = true;
    }

    private synchronized Set<Long> makeAllCtxs(KeyManager[] kms, TrustManager[] tms, final long ctx) throws KeyManagementException {
        // a single subject can have multiple certificates for different algorithms, as
        // aliases are required to be unique, the subject is the next best thing to establish
        // some form of grouping, as a single context can have multiple certificates
        // for different algorithms
        final Map<String, Long> subjectToSSLContextMap = new LinkedHashMap<>();

        // this simple map is used later on during certificate selection in the SNICallback,
        // as a single ssl ctx can have multiple certificate, and SNI uses a requested
        // hostname to allow the server to choose the certificate, we flatten everything
        final Map<SNIMatcher, Long> x509CertificateToSSLContextMap = new LinkedHashMap<>();

        long defaultAliasCtx = 0L;

        try {
            // Load Server key and certificate
            X509KeyManager keyManager = chooseKeyManager(kms);
            if (keyManager != null) {
                for (String algorithm : ALGORITHMS) {

                    int counter = 0;

                    boolean rsa = algorithm.equals("RSA");
                    final String[] aliases = keyManager.getServerAliases(algorithm, null);
                    if (aliases != null && aliases.length != 0) {
                        for(String alias: aliases) {

                            counter++;
                            X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
                            PrivateKey key = keyManager.getPrivateKey(alias);
                            if(key == null || certificateChain == null || key.getEncoded() == null) {
                                continue;
                            }
                            if (LOG.isLoggable(Level.FINE)) {
                                LOG.fine("Using alias " + alias + " for " + algorithm);
                            }
                            StringBuilder sb = new StringBuilder(rsa ? BEGIN_RSA_CERT : BEGIN_DSA_CERT);
                            byte[] encodedPrivateKey = key.getEncoded();
                            if (encodedPrivateKey == null) {
                                throw new KeyManagementException(Messages.MESSAGES.unableToObtainPrivateKey());
                            }
                            sb.append(Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encodedPrivateKey));
                            sb.append(rsa ? END_RSA_CERT : END_DSA_CERT);

                            byte[][] encodedIntermediaries = new byte[certificateChain.length - 1][];
                            for(int i = 1; i < certificateChain.length; ++i) {
                                encodedIntermediaries[i - 1] = certificateChain[i].getEncoded();
                            }
                            X509Certificate certificate = certificateChain[0];

                            // for a single subject multiple certificates with different algorithms can exist, if
                            // we already have a context for a specific subject, use it, otherwise generate a new context
                            // to be used with SNI
                            Long sslCtx = subjectToSSLContextMap.get(certificate.getSubjectX500Principal().getName());

                            // if no existing context could be found, and this is the first round, establish the
                            // "default" context
                            if (sslCtx == null) {
                                if (counter == 1) {
                                    sslCtx = ctx;
                                } else {
                                    sslCtx = makeSSLContext();
                                }

                                subjectToSSLContextMap.put(certificate.getSubjectX500Principal().getName(), sslCtx);
                            }

                            if (alias.equals(SSL_KEYSTORE_DEFAULT_ALIAS)) {
                                if (LOG.isLoggable(Level.FINE)) {
                                    LOG.fine("Setting defaultSSLContext to: " + sslCtx);
                                }
                                defaultAliasCtx = sslCtx;
                            }

                            // set the certificates to use for this context
                            SSL.getInstance().setCertificate(sslCtx, certificate.getEncoded(), encodedIntermediaries, sb.toString().getBytes(StandardCharsets.US_ASCII), rsa ? SSL.SSL_AIDX_RSA : SSL.SSL_AIDX_DSA);
                            x509CertificateToSSLContextMap.put(SNIUtil.getHostnamesSNIMatcherFromCertificate(certificate), sslCtx);
                        }
                    }
                }
            }

            final long defaultSSLContext = defaultAliasCtx;

            if (x509CertificateToSSLContextMap.size() > 1) {
                SSL.registerDefault(ctx, new SSL.SNICallBack() {

                  @Override
                  public long getSslContext(String sniHostName) {
                    if (sniHostName == null || sniHostName.isEmpty()) {
                      return ctx;
                    }

                    final SNIMatcher sniBestMatch = SNIUtil.getBestSniHostNameMatch(sniHostName, x509CertificateToSSLContextMap.keySet());
                    long wildcardSSLContext = sniBestMatch != null ? x509CertificateToSSLContextMap.get(sniBestMatch) : 0L;

                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.fine( "sniHostName:" + sniHostName + " ctx:" + ctx + " wildcardSSLContext:" + wildcardSSLContext + " defaultSSLContext:" + defaultSSLContext);
                    }

                    // if we have a ssl ctx with a matching wildcard cert, prefer it, otherwise use the defaultSSLContext
                    return wildcardSSLContext != 0L ? wildcardSSLContext : defaultSSLContext != 0L ? defaultSSLContext : ctx;
                  }
                });
            }

            /*
            // Support Client Certificates
            SSL.getInstance().setCACertificate(ctx,
                    SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificateFile()),
                    SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificatePath()));
            // Set revocation
            SSL.getInstance().setCARevocation(ctx,
                    SSLHostConfig.adjustRelativePath(
                            sslHostConfig.getCertificateRevocationListFile()),
                    SSLHostConfig.adjustRelativePath(
                            sslHostConfig.getCertificateRevocationListPath()));
            */
            // Client certificate verification

            final Set<Long> sslContexts = new HashSet<>(x509CertificateToSSLContextMap.values());

            if (sslContexts.isEmpty()) {
                configureSSLContext(tms, ctx);
            } else {
                for (long sslCtx : sslContexts) {
                    configureSSLContext(tms, sslCtx);
                }
            }

            //TODO: ALPN must be optional
            SSL.getInstance().enableAlpn(ctx);

            return sslContexts.isEmpty() ? new HashSet<>(Arrays.asList(ctx)) : sslContexts;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected boolean verifyCallback(final X509TrustManager manager, long ssl, byte[][] chain, int cipherNo, boolean server) {
        X509Certificate[] peerCerts = certificates(chain);
        Cipher cipher = Cipher.valueOf(cipherNo);
        String auth = cipher == null ? "RSA" : cipher.getAu().toString();
        try {
            if(server) {
                manager.checkClientTrusted(peerCerts, auth);
            } else {
                manager.checkServerTrusted(peerCerts, auth);
            }
            return true;
        } catch (Exception e) {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Certificate verification failed", e);
            }
        }
        return false;
    }

    private void configureSSLContext(final TrustManager[] tms, final long sslCtx) {
        SSL.getInstance().setSessionCacheSize(sslCtx, DEFAULT_SESSION_CACHE_SIZE);
        final X509TrustManager manager = chooseTrustManager(tms);
        if(manager != null) {
            SSL.getInstance().setCertVerifyCallback(sslCtx, new OpenSSLCertVerifyCallback(manager, this));
        }
    }

    private X509KeyManager chooseKeyManager(KeyManager[] tms) {
        if(tms == null) {
            return null;
        }
        for (KeyManager tm : tms) {
            if (tm instanceof X509KeyManager) {
                return (X509KeyManager) tm;
            }
        }
        throw new IllegalStateException(Messages.MESSAGES.keyManagerIsMissing());
    }

    static X509TrustManager chooseTrustManager(TrustManager[] managers) {
        if(managers == null) {
            try {
                TrustManagerFactory instance = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                instance.init((KeyStore)null);
                managers = instance.getTrustManagers();
            } catch (NoSuchAlgorithmException|KeyStoreException e) {
                throw new IllegalArgumentException(e);
            }
        }
        for (TrustManager m : managers) {
            if (m instanceof X509TrustManager) {
                return (X509TrustManager) m;
            }
        }
        throw new IllegalStateException(Messages.MESSAGES.trustManagerIsMissing());
    }

    private static X509Certificate[] certificates(byte[][] chain) {
        X509Certificate[] peerCerts = new X509Certificate[chain.length];
        for (int i = 0; i < peerCerts.length; i++) {
            peerCerts[i] = new OpenSslX509Certificate(chain[i]);
        }
        return peerCerts;
    }

    public SSLSessionContext getServerSessionContext() {
        return serverSessionContext;
    }

    public SSLEngine createSSLEngine() {
        return new OpenSSLEngine(serverCtx, false, OpenSSLContextSPI.this);
    }

    public SSLEngine createSSLEngine(final String host, final int port) {
        return new OpenSSLEngine(serverCtx, false, OpenSSLContextSPI.this, host, port);
    }


    public String[] getCiphers() {
        if(ciphers == null) {
            synchronized (this) {
                if(ciphers == null) {
                    OpenSSLEngine engine = (OpenSSLEngine) createSSLEngine();
                    engine.initSsl();
                    ciphers = engine.getEnabledCipherSuites();
                }
            }
        }
        return ciphers.clone();
    }

    @Override
    protected final void finalize() throws Throwable {
        super.finalize();
        synchronized (OpenSSLContextSPI.class) {
            for (long ctx : allServerCtxs) {
                if (ctx != 0) {
                    SSL.getInstance().freeSSLContext(ctx);
                }
            }
            for (long ctx : allClientCtxs) {
                if (ctx != 0) {
                    SSL.getInstance().freeSSLContext(ctx);
                }
            }
        }
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        init(km, tm);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return new SSLSocketFactory() {
            @Override
            public String[] getDefaultCipherSuites() {
                throw new UnsupportedOperationException();
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return getCiphers().clone();
            }

            @Override
            public Socket createSocket() throws IOException {
                return new OpenSSLSocket(new OpenSSLEngine(clientCtx, true, OpenSSLContextSPI.this));
            }

            @Override
            public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
                return new OpenSSLSocket(s, autoClose, host, port, new OpenSSLEngine(clientCtx, true, OpenSSLContextSPI.this, host, port));
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
                return new OpenSSLSocket(host, port, new OpenSSLEngine(clientCtx, true, OpenSSLContextSPI.this, host, port));
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
                return new OpenSSLSocket(host, port, localHost, localPort, new OpenSSLEngine(clientCtx, true, OpenSSLContextSPI.this, host, port));
            }

            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                return new OpenSSLSocket(host, port, new OpenSSLEngine(clientCtx, true, OpenSSLContextSPI.this, host.getHostName(), port));
            }

            @Override
            public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                return new OpenSSLSocket(address, port, localAddress, localPort, new OpenSSLEngine(clientCtx, true, OpenSSLContextSPI.this, address.getHostName(), port));
            }
        };
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return new SSLServerSocketFactory() {
            @Override
            public String[] getDefaultCipherSuites() {
                throw new UnsupportedOperationException();
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return getCiphers().clone();
            }

            @Override
            public ServerSocket createServerSocket(int port) throws IOException {
                return new OpenSSLServerSocket(port, OpenSSLContextSPI.this);
            }

            @Override
            public ServerSocket createServerSocket(int port, int backlog) throws IOException {
                return new OpenSSLServerSocket(port, backlog, OpenSSLContextSPI.this);
            }

            @Override
            public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
                return new OpenSSLServerSocket(port, backlog, ifAddress, OpenSSLContextSPI.this);
            }
        };
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return createSSLEngine(host, port);
    }

    @Override
    protected OpenSSLServerSessionContext engineGetServerSessionContext() {
        return serverSessionContext;
    }

    @Override
    protected OpenSSLClientSessionContext engineGetClientSessionContext() {
        return clientSessionContext;
    }

    public void sessionRemoved(byte[] session) {
        serverSessionContext.remove(session);
    }

    public static final class OpenSSLTLSContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLSContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_ALL);
        }
    }

    public static final class OpenSSLTLS_1_0_ContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLS_1_0_ContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_TLSV1);
        }
    }

    public static final class OpenSSLTLS_1_1_ContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLS_1_1_ContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_TLSV1_1);
        }
    }

    public static final class OpenSSLTLS_1_2_ContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLS_1_2_ContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_TLSV1_2);
        }
    }

    public static final class OpenSSLTLS_1_3_ContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLS_1_3_ContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_TLSV1_3);
        }
    }
}

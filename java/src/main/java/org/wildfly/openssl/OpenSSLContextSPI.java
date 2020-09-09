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


import static org.wildfly.openssl.OpenSSLEngine.isTLS13Supported;

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
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
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

public abstract class OpenSSLContextSPI extends SSLContextSpi {

    private static final Logger LOG = Logger.getLogger(OpenSSLContextSPI.class.getName());

    public static final int DEFAULT_SESSION_CACHE_SIZE = 1000;

    private static final String BEGIN_RSA_CERT = "-----BEGIN RSA PRIVATE KEY-----\n";

    private static final String END_RSA_CERT = "\n-----END RSA PRIVATE KEY-----";

    private static final String BEGIN_DSA_CERT = "-----BEGIN DSA PRIVATE KEY-----\n";

    private static final String END_DSA_CERT = "\n-----END DSA PRIVATE KEY-----";

    private static final String[] ALGORITHMS = {"RSA", "DSA"};

    private OpenSSLServerSessionContext serverSessionContext;
    private OpenSSLClientSessionContext clientSessionContext;

    private static volatile String[] allAvailableCiphers;

    private static final String TLS13_CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";

    protected final long ctx;
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
        try {
            // Create SSL Context
            try {
                ctx = SSL.getInstance().makeSSLContext(value, SSL.SSL_MODE_COMBINED);
            } catch (Exception e) {
                // If the sslEngine is disabled on the AprLifecycleListener
                // there will be an Exception here but there is no way to check
                // the AprLifecycleListener settings from here
                throw new SSLException(Messages.MESSAGES.failedToMakeSslContext(), e);
            }
            try {
                //disable unsafe renegotiation
                SSL.getInstance().clearSSLContextOptions(ctx, SSL.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            // Disable compression
            boolean disableCompressionSupported = false;
            try {
                disableCompressionSupported = SSL.getInstance().hasOp(SSL.SSL_OP_NO_COMPRESSION);
                if (disableCompressionSupported) {
                    SSL.getInstance().setSSLContextOptions(ctx, SSL.SSL_OP_NO_COMPRESSION);
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!disableCompressionSupported) {
                LOG.fine("The version of SSL in use does not support disabling compression");
            }

            // Disable TLS Session Tickets (RFC4507) to protect perfect forward secrecy
            boolean disableSessionTicketsSupported = false;
            try {
                disableSessionTicketsSupported = SSL.getInstance().hasOp(SSL.SSL_OP_NO_TICKET);
                if (disableSessionTicketsSupported) {
                    SSL.getInstance().setSSLContextOptions(ctx, SSL.SSL_OP_NO_TICKET);
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!disableSessionTicketsSupported) {
                // OpenSSL is too old to support TLS Session Tickets.
                LOG.fine("The version of SSL in use does not support disabling session tickets");
            }
        } catch (Exception e) {
            throw new RuntimeException(Messages.MESSAGES.failedToInitializeSslContext(), e);
        }

    }

    /**
     * Setup the SSL_CTX
     *
     * @param kms Must contain a KeyManager of the type
     *            {@code OpenSSLKeyManager}
     * @param tms
     */
    private synchronized void init(KeyManager[] kms, TrustManager[] tms) throws KeyManagementException {
        if (initialized) {
            LOG.warning(Messages.MESSAGES.ignoringSecondInit());
            return;
        }

        try {
            // Load Server key and certificate
            X509KeyManager keyManager = chooseKeyManager(kms);
            if (keyManager != null) {
                for (String algorithm : ALGORITHMS) {

                    boolean rsa = algorithm.equals("RSA");
                    final String[] aliases = keyManager.getServerAliases(algorithm, null);
                    if (aliases != null && aliases.length != 0) {
                        for(String alias: aliases) {

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
                            SSL.getInstance().setCertificate(ctx, certificate.getEncoded(), encodedIntermediaries, sb.toString().getBytes(StandardCharsets.US_ASCII), rsa ? SSL.SSL_AIDX_RSA : SSL.SSL_AIDX_DSA);
                            break;
                        }
                    }
                }
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

            SSL.getInstance().setSessionCacheSize(ctx, DEFAULT_SESSION_CACHE_SIZE);
            final X509TrustManager manager = chooseTrustManager(tms);
            if(manager != null) {
                SSL.getInstance().setCertVerifyCallback(ctx, (ssl, chain, cipherNo, server) -> {
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
                });
            }


            serverSessionContext = new OpenSSLServerSessionContext(ctx);
            serverSessionContext.setSessionIdContext("test".getBytes(StandardCharsets.US_ASCII));
            clientSessionContext = new OpenSSLClientSessionContext(ctx);
            initialized = true;

            //TODO: ALPN must be optional
            SSL.getInstance().enableAlpn(ctx);

        } catch (Exception e) {
            throw new RuntimeException(e);
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
        return new OpenSSLEngine(ctx, false, OpenSSLContextSPI.this);
    }

    public SSLEngine createSSLEngine(final String host, final int port) {
        return new OpenSSLEngine(ctx, false, OpenSSLContextSPI.this, host, port);
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
            if (ctx != 0) {
                SSL.getInstance().freeSSLContext(ctx);
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
                return new OpenSSLSocket(new OpenSSLEngine(ctx, true, OpenSSLContextSPI.this));
            }

            @Override
            public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
                return new OpenSSLSocket(s, autoClose, host, port, new OpenSSLEngine(ctx, true, OpenSSLContextSPI.this, host, port));
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
                return new OpenSSLSocket(host, port, new OpenSSLEngine(ctx, true, OpenSSLContextSPI.this, host, port));
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
                return new OpenSSLSocket(host, port, localHost, localPort, new OpenSSLEngine(ctx, true, OpenSSLContextSPI.this, host, port));
            }

            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                return new OpenSSLSocket(host, port, new OpenSSLEngine(ctx, true, OpenSSLContextSPI.this, host.getHostName(), port));
            }

            @Override
            public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                return new OpenSSLSocket(address, port, localAddress, localPort, new OpenSSLEngine(ctx, true, OpenSSLContextSPI.this, address.getHostName(), port));
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

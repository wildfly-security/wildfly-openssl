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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author Stuart Douglas
 */
public class SSLTestUtils {

    public static final String HOST = System.getProperty("org.wildfly.openssl.test.host", "localhost");
    public static final int PORT = Integer.parseInt(System.getProperty("org.wildfly.openssl.test.port", "7677"));
    public static final int SECONDARY_PORT = Integer.parseInt(System.getProperty("org.wildfly.openssl.test.secondary.port", "7687"));

    private static KeyStore loadKeyStore(final String name) throws IOException {
        final InputStream stream = BasicOpenSSLEngineTest.class.getClassLoader().getResourceAsStream(name);
        try {
            KeyStore loadedKeystore = KeyStore.getInstance("JKS");
            loadedKeystore.load(stream, "password".toCharArray());

            return loadedKeystore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(String.format("Unable to load KeyStore %s", name), e);
        } finally {
            stream.close();
        }
    }

    private static SSLContext createSSLContext(String provider, String keystore, String truststore) throws IOException {
        KeyManager[] keyManagers = null;
        if (keystore != null) {
            try {
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(loadKeyStore(keystore), "password".toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
                throw new RuntimeException("Unable to initialise KeyManager[]", e);
            }
        }

        TrustManager[] trustManagers = null;
        if (truststore != null) {
            try {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(loadKeyStore(truststore));
                trustManagers = trustManagerFactory.getTrustManagers();
            } catch (NoSuchAlgorithmException | KeyStoreException e) {
                throw new RuntimeException("Unable to initialise TrustManager[]", e);
            }
        }

        try {
            final SSLContext context = SSLContext.getInstance(provider);
            context.init(keyManagers, trustManagers, new SecureRandom());
            return context;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Unable to create and initialise the SSLContext", e);
        }
    }

    static SSLContext createSSLContext(String provider) throws IOException {
        return createSSLContext(provider, "server.keystore", "server.truststore");
    }

    static SSLContext createClientSSLContext(String provider) throws IOException {
        return createSSLContext(provider, "client.keystore", "client.truststore");
    }

    static SSLContext createDSASSLContext(String provider) throws IOException {
        return createSSLContext(provider, "server-dsa.keystore", null);
    }

    static SSLContext createClientDSASSLContext(String provider) throws IOException {
        return createSSLContext(provider, null, "client-dsa.truststore");
    }

    static SSLContext createECSSLContext(String provider) throws IOException {
        return createSSLContext(provider, "server-ec.keystore", "server-ec.truststore");
    }

    static SSLContext createClientECSSLContext(String provider) throws IOException {
        return createSSLContext(provider, "client-ec.keystore", "client-ec.truststore");
    }

    public static byte[] readData(InputStream in) throws IOException {
        int r;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        while ((r = in.read(buf)) > 0) {
            out.write(buf, 0, r);
        }
        return out.toByteArray();
    }

    public static ServerSocket createServerSocket() throws IOException {
        return createServerSocket(PORT);
    }

    public static ServerSocket createServerSocket(final int port) throws IOException {
        ServerSocket serverSocket = new ServerSocket(port);
        serverSocket.setReuseAddress(true);
        return serverSocket;
    }

    public static SocketAddress createSocketAddress() {
        return new InetSocketAddress(HOST, PORT);
    }

}

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

import static org.wildfly.openssl.OpenSSLEngine.isOpenSSL10;
import static org.wildfly.openssl.OpenSSLEngine.isOpenSSL110FOrLower;
import static org.wildfly.openssl.OpenSSLEngine.isOpenSSL300OrHigher;
import static org.wildfly.openssl.OpenSSLEngine.isTLS13Supported;
import static org.wildfly.openssl.OpenSSLProvider.getJavaSpecVersion;
import static org.wildfly.openssl.SSL.SSL_PROTO_SSLv2;
import static org.wildfly.openssl.SSL.SSL_PROTO_SSLv2Hello;
import static org.wildfly.openssl.SSL.SSL_PROTO_SSLv3;
import static org.wildfly.openssl.SSL.SSL_PROTO_TLSv1;
import static org.wildfly.openssl.SSL.SSL_PROTO_TLSv1_1;
import static org.wildfly.openssl.SSL.SSL_PROTO_TLSv1_2;
import static org.wildfly.openssl.SSL.SSL_PROTO_TLSv1_3;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests that make use of legacy TLS protocols. Since legacy TLS protocols have been disabled
 * in newer JDK versions, this test class ensures that these protocols are re-enabled if necessary
 * to make sure the protocols are actually available for the tests.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class BasicOpenSSLEngineLegacyProtocolsTest extends AbstractOpenSSLTest  {

    public static final String MESSAGE = "Hello World";
    public static String disabledAlgorithms;

    // @SECLEVEL=1 is a needed directive to enable security level 1
    private static final String[] RSA_CIPHERS_SECLEVEL_1 = {
        "@SECLEVEL=1", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"
    };

    @BeforeClass
    public static void setUp() {
        disabledAlgorithms = Security.getProperty("jdk.tls.disabledAlgorithms");
        if (disabledAlgorithms != null && (disabledAlgorithms.contains(SSL_PROTO_TLSv1) || disabledAlgorithms.contains(SSL_PROTO_TLSv1_1))) {
            // reset the disabled algorithms to make sure that the protocols required in this test are available
            Security.setProperty("jdk.tls.disabledAlgorithms", "");
        }
    }

    @AfterClass
    public static void cleanUp() {
        if (disabledAlgorithms != null) {
            Security.setProperty("jdk.tls.disabledAlgorithms", disabledAlgorithms);
        }
    }

    private final String[] PROTOCOLS = {
            SSL_PROTO_SSLv2,
            SSL_PROTO_SSLv3,
            SSL_PROTO_TLSv1,
            SSL_PROTO_TLSv1_1,
            SSL_PROTO_TLSv1_2,
            SSL_PROTO_TLSv1_3
    };

    private String[] expectedEngineProtocols(String[] serverProtocols) {
        int min = PROTOCOLS.length;
        int max= -1;
        for (String protocol : serverProtocols) {
            for (int i = 0; i < PROTOCOLS.length; i++) {
                if (PROTOCOLS[i].equals(protocol)) {
                    if (i < min) {
                        min = i;
                    }
                    if (i > max) {
                        max = i;
                    }
                }
            }
        }
        List<String> result = new ArrayList<>();
        result.add(SSL_PROTO_SSLv2Hello);
        for (int i = min; i <= max; i++) {
            result.add(PROTOCOLS[i]);
        }
        return result.toArray(new String[0]);
    }

    private void testSocket(String protocol, String[] serverProtocols, AtomicReference<SSLEngine> engineRef, AtomicReference<byte[]> sessionID) throws IOException {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(new String[]{protocol}); // from list of enabled protocols on the server side
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (!SSL_PROTO_TLSv1_3.equals(protocol)) {
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            }
            Assert.assertEquals(protocol, socket.getSession().getProtocol());
            Assert.assertArrayEquals(expectedEngineProtocols(serverProtocols), engineRef.get().getEnabledProtocols());
            socket.getSession().invalidate();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolExactMatch() throws IOException, InterruptedException {
        Assume.assumeTrue(!isOpenSSL300OrHigher());
        final String[] protocols = new String[] { SSL_PROTO_TLSv1, SSL_PROTO_TLSv1_1 };
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    if (!isOpenSSL10()) {
                        engine.setEnabledCipherSuites(RSA_CIPHERS_SECLEVEL_1);
                    }
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            testSocket(SSL_PROTO_TLSv1, protocols, engineRef, sessionID);
            testSocket(SSL_PROTO_TLSv1_1, protocols, engineRef, sessionID);

            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolExactMatchTls13() throws IOException, InterruptedException {
        Assume.assumeTrue(isTLS13Supported());
        final String[] protocols = new String[] { SSL_PROTO_TLSv1_2, SSL_PROTO_TLSv1_3 };
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            testSocket(SSL_PROTO_TLSv1_2, protocols, engineRef, sessionID);
            testSocket(SSL_PROTO_TLSv1_3, protocols, engineRef, sessionID);

            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolWithinEnabledRange() throws IOException, InterruptedException {
        Assume.assumeTrue(! isOpenSSL10() && ! isOpenSSL110FOrLower() && ! isOpenSSL300OrHigher());
        final String[] protocols = new String[] { SSL_PROTO_TLSv1, SSL_PROTO_TLSv1_2 };
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    if (!isOpenSSL10()) {
                        engine.setEnabledCipherSuites(RSA_CIPHERS_SECLEVEL_1);
                    }
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            testSocket(SSL_PROTO_TLSv1_1, protocols, engineRef, sessionID);

            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolWithinEnabledRangeTls13() throws IOException, InterruptedException {
        Assume.assumeTrue(isTLS13Supported());
        final String[] protocols = new String[] { SSL_PROTO_TLSv1_1, SSL_PROTO_TLSv1_3 };
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            testSocket(SSL_PROTO_TLSv1_2, protocols, engineRef, sessionID);

            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolOutsideOfEnabledRange() throws IOException, InterruptedException {
        final String[] protocols = new String[]{SSL_PROTO_TLSv1_1, SSL_PROTO_TLSv1_2};
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    if (!isOpenSSL10()) {
                        engine.setEnabledCipherSuites(RSA_CIPHERS_SECLEVEL_1);
                    }
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            try {
                testSocket(SSL_PROTO_SSLv3, protocols, engineRef, sessionID);
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
            }
            try {
                testSocket(SSL_PROTO_TLSv1, protocols, engineRef, sessionID);
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
            }
            try {
                if (getJavaSpecVersion() >= 11) {
                    testSocket(SSL_PROTO_TLSv1_3, protocols, engineRef, sessionID);
                    Assert.fail("Expected SSLHandshakeException not thrown");
                }
            } catch (SSLHandshakeException e) {
                // expected
            }

            serverSocket.close();
            acceptThread.join();
        }
    }
}

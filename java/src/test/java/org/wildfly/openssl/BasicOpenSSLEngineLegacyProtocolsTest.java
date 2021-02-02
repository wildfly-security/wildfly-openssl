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
import static org.wildfly.openssl.OpenSSLProvider.getJavaSpecVersion;
import static org.wildfly.openssl.SSL.SSL_PROTO_SSLv2Hello;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.Security;
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

    @BeforeClass
    public static void setUp() {
        disabledAlgorithms = Security.getProperty("jdk.tls.disabledAlgorithms");
        if (disabledAlgorithms != null && (disabledAlgorithms.contains("TLSv1") || disabledAlgorithms.contains("TLSv1.1"))) {
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

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolExactMatch() throws IOException, InterruptedException {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1" };
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

            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(new String[]{"TLSv1"}); // from list of enabled protocols on the server side
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1"}, engineRef.get().getEnabledProtocols());
            socket.getSession().invalidate();
            socket.close();

            socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(new String[]{"TLSv1.1"}); // from list of enabled protocols on the server side
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            data = new byte[100];
            read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1.1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1"}, engineRef.get().getEnabledProtocols());

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolWithinEnabledRange() throws IOException, InterruptedException {
        Assume.assumeTrue(! isOpenSSL10() && ! isOpenSSL110FOrLower());
        final String[] protocols = new String[] { "TLSv1", "TLSv1.2" };
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

            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(new String[] { "TLSv1.1" });
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1.1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1", "TLSv1.2"}, engineRef.get().getEnabledProtocols());

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolOutsideOfEnabledRange() throws IOException, InterruptedException {
        final String[] protocols = new String[]{"TLSv1.1", "TLSv1.2"};
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

            SSLSocket socket = null;
            try {
                socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                socket.setReuseAddress(true);
                socket.setEnabledProtocols(new String[]{"SSLv3"});
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
                if (socket != null) {
                    socket.close();
                }
            }
            try {
                socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                socket.setReuseAddress(true);
                socket.setEnabledProtocols(new String[]{"TLSv1"});
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
                if (socket != null) {
                    socket.close();
                }
            }
            try {
                if (getJavaSpecVersion() >= 11) {
                    socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                    socket.setReuseAddress(true);
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    socket.connect(SSLTestUtils.createSocketAddress());
                    socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                    Assert.fail("Expected SSLHandshakeException not thrown");
                }
            } catch (SSLHandshakeException e) {
                // expected
                if (socket != null) {
                    socket.close();
                }
            }

            serverSocket.close();
            acceptThread.join();
        }
    }
}

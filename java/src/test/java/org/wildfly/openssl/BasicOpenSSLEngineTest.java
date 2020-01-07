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

import static org.wildfly.openssl.SSL.SSL_PROTO_SSLv2Hello;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class BasicOpenSSLEngineTest extends AbstractOpenSSLTest  {

    public static final String MESSAGE = "Hello World";
    private static final String javaSpecVersion = System.getProperty("java.specification.version");

    static int getJavaSpecVersion() {
        if ("1.8".equals(javaSpecVersion)) return 8;
        return Integer.parseInt(javaSpecVersion);
    }

    @Test
    public void basicOpenSSLTest() throws IOException, NoSuchAlgorithmException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1");

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID));
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testNoExplicitEnabledProtocols() throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1.2", socket.getSession().getProtocol());
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testSingleEnabledProtocol() throws IOException, InterruptedException {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String protocol : protocols) {
            try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
                final AtomicReference<byte[]> sessionID = new AtomicReference<>();
                final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
                final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

                EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                    engineRef.set(engine);
                    try {
                        engine.setEnabledProtocols(new String[]{ protocol }); // only one protocol enabled on server side
                        return engine;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }));
                Thread acceptThread = new Thread(echo);
                acceptThread.start();
                final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                byte[] data = new byte[100];
                int read = socket.getInputStream().read(data);

                Assert.assertEquals(MESSAGE, new String(data, 0, read));
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                Assert.assertEquals(protocol, socket.getSession().getProtocol());
                Assert.assertArrayEquals(new String[]{ SSL_PROTO_SSLv2Hello, protocol }, engineRef.get().getEnabledProtocols());
                socket.getSession().invalidate();
                socket.close();
                serverSocket.close();
                acceptThread.join();
            }
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
            socket.setEnabledProtocols(new String[] { "TLSv1" }); // from list of enabled protocols on the server side
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{ SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1" }, engineRef.get().getEnabledProtocols());
            socket.getSession().invalidate();
            socket.close();

            socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setEnabledProtocols(new String[] { "TLSv1.1" }); // from list of enabled protocols on the server side
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            data = new byte[100];
            read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1.1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{ SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1"}, engineRef.get().getEnabledProtocols());

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolWithinEnabledRange() throws IOException, InterruptedException {
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
            socket.setEnabledProtocols(new String[] { "TLSv1.1" });
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1.1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{ SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1", "TLSv1.2" }, engineRef.get().getEnabledProtocols());

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolOutsideOfEnabledRange() throws IOException, InterruptedException {
        final String[] protocols = new String[] { "TLSv1.1", "TLSv1.2" };

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

            try {
                SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                socket.setEnabledProtocols(new String[]{"SSLv3"});
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
            }
            try {
                SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                socket.setEnabledProtocols(new String[]{"TLSv1"});
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
            }
            try {
                if (getJavaSpecVersion() >= 11) {
                    SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    socket.connect(SSLTestUtils.createSocketAddress());
                    socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                    Assert.fail("Expected SSLHandshakeException not thrown");
                }
            } catch (SSLHandshakeException e) {
                // expected
            }

            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test(expected = SSLException.class)
    public void testWrongClientSideTrustManagerFailsValidation() throws IOException, NoSuchAlgorithmException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1");

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID));
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLTestUtils.createSSLContext("openssl.TLSv1").getSocketFactory().createSocket();
            socket.setSSLParameters(socket.getSSLParameters());
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }


    @Test
    public void openSslLotsOfDataTest() throws IOException, NoSuchAlgorithmException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1");

            EchoRunnable target = new EchoRunnable(serverSocket, sslContext, sessionID);
            Thread acceptThread = new Thread(target);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.connect(SSLTestUtils.createSocketAddress());
            String message = generateMessage(1000);
            socket.getOutputStream().write(message.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(new byte[]{0});

            Assert.assertEquals(message, new String(SSLTestUtils.readData(socket.getInputStream())));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());

            serverSocket.close();
            acceptThread.join();
        }
    }

    private static String generateMessage(int repetitions) {
        final StringBuilder builder = new StringBuilder(repetitions * MESSAGE.length());
        for (int i = 0; i < repetitions; ++i) {
            builder.append(MESSAGE);
        }
        return builder.toString();
    }
}

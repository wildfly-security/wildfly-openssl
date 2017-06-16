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

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class ALPNTest extends AbstractOpenSSLTest {

    public static final String MESSAGE = "Hello World";

    @Test
    public void testALPN() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(OpenSSLEngine.isAlpnSupported());
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.2");
            final AtomicReference<OpenSSLEngine> engineAtomicReference = new AtomicReference<>();
            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                OpenSSLEngine openSSLEngine = (OpenSSLEngine) engine;
                openSSLEngine.setApplicationProtocols("h2", "h2/13", "http");
                engineAtomicReference.set(openSSLEngine);
                return openSSLEngine;
            })));
            acceptThread.start();

            final SSLContext clientSslContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1.2");
            final OpenSSLSocket socket = (OpenSSLSocket) clientSslContext.getSocketFactory().createSocket();
            socket.setApplicationProtocols("h2/13", "h2", "http");
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertEquals("server side", "h2", engineAtomicReference.get().getSelectedApplicationProtocol());
            Assert.assertEquals("client side", "h2", socket.getSelectedApplicationProtocol());
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testALPNFailure() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(OpenSSLEngine.isAlpnSupported());
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.2");
            final SSLContext clientSslContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1.2");
            final AtomicReference<OpenSSLEngine> engineAtomicReference = new AtomicReference<>();
            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                OpenSSLEngine openSSLEngine = (OpenSSLEngine) engine;
                openSSLEngine.setApplicationProtocols("h2", "h2/13", "http");
                engineAtomicReference.set(openSSLEngine);
                return openSSLEngine;
            })));
            acceptThread.start();
            final OpenSSLSocket socket = (OpenSSLSocket) clientSslContext.getSocketFactory().createSocket();
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertNull("server side", engineAtomicReference.get().getSelectedApplicationProtocol());
            Assert.assertNull("client side", socket.getSelectedApplicationProtocol());
            serverSocket.close();
            acceptThread.join();
        }
    }
}

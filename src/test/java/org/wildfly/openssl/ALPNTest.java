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
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class ALPNTest {

    public static final String MESSAGE = "Hello World";

    @BeforeClass
    public static void setup() {
        OpenSSLProvider.register();
    }

    @Test
    public void testALPN() throws IOException, NoSuchAlgorithmException {
        try (ServerSocket serverSocket = new ServerSocket(7676)) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1");
            final AtomicReference<OpenSSLEngine> engineAtomicReference = new AtomicReference<>();
            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                OpenSSLEngine openSSLEngine = (OpenSSLEngine) engine;
                openSSLEngine.setApplicationProtocols("h2", "h2/13", "http");
                engineAtomicReference.set(openSSLEngine);
                return openSSLEngine;
            })));
            acceptThread.start();
            final OpenSSLSocket socket = (OpenSSLSocket) sslContext.getSocketFactory().createSocket();
            socket.setApplicationProtocols("h2/13", "h2", "http");
            socket.connect(new InetSocketAddress("localhost", 7676));
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("server side", "h2", engineAtomicReference.get().getSelectedApplicationProtocol());
            Assert.assertEquals("client side", "h2", socket.getSelectedApplicationProtocol());
        }
    }

}

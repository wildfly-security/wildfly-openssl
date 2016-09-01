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
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class SslCiphersTest extends AbstractOpenSSLTest {

    @BeforeClass
    public static void setup() {
        OpenSSLProvider.register();
    }

    @Test
    public void testCipherSuiteConverter() throws IOException {

        final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
        for (String cipher : socket.getSupportedCipherSuites()) {
            if (cipher.contains("EMPTY")) {
                continue;
            }
            String openSslCipherSuite = CipherSuiteConverter.toOpenSsl(cipher);
            Assert.assertNotNull(cipher, openSslCipherSuite);
            Assert.assertEquals(cipher, CipherSuiteConverter.toJava(openSslCipherSuite, cipher.substring(0, 3)));
        }
    }

    @Test
    public void testAvailableProtocols() throws Exception {
        final AtomicReference<byte[]> sessionID = new AtomicReference<>();
        final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.2");

        //we only test a subset of ciphers
        //TODO: figure out which ones we need to support, and what sort of cert we need for each
        String[] suites = new String[]{
                //"TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                //"TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                //"TLS_RSA_WITH_AES_256_CBC_SHA"
        };

        for (String suite : suites) {

            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            ServerSocket serverSocket = SSLTestUtils.createServerSocket();
            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledCipherSuites(new String[]{suite});
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setEnabledCipherSuites(new String[]{suite});
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals("hello world", new String(data, 0, read));
            //make sure the names match
            String cipherSuite = socket.getSession().getCipherSuite();
            SSLEngine sslEngine = engineRef.get();
            SSLSession session = sslEngine.getSession();
            // SSL is an alias for TLS, Windows and IBM J9 seem to use SSL for simplicity we'll just replace SSL with
            // TLS to match what we're expecting
            if(cipherSuite.startsWith("SSL")) {
                cipherSuite = cipherSuite.replace("SSL", "TLS");
            }
            Assert.assertEquals(session.getCipherSuite(), cipherSuite);
            Assert.assertEquals(session.getCipherSuite(), suite);
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            socket.getSession().invalidate();
            socket.close();
            echo.stop();
            serverSocket.close();
            acceptThread.join();
        }
    }
}

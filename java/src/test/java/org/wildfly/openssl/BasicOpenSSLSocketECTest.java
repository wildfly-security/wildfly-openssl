/*
 * JBoss, Home of Professional Open Source.
 *
 * Copyright 2022 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import static org.wildfly.openssl.OpenSSLEngine.isTLS13Supported;
import static org.wildfly.openssl.SSL.SSL_PROTO_TLSv1_2;
import static org.wildfly.openssl.SSL.SSL_PROTO_TLSv1_3;

/**
 * <p>Test class that uses TLSv1.2 and TLSv1.3 to connect a client and server
 * using openssl engine and the EC certificates.</p>
 *
 * @author rmartinc
 */
public class BasicOpenSSLSocketECTest extends AbstractOpenSSLTest {

    public void testECCertificates(String protocol, boolean opensslClient, boolean opensslServer) throws IOException, NoSuchAlgorithmException, InterruptedException {

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket,
                    SSLTestUtils.createECSSLContext(opensslServer? "openssl." + protocol : protocol), sessionID,
                    engine -> {
                        engine.setNeedClientAuth(true);
                        engineRef.set(engine);
                        return engine;
                    }));
            acceptThread.start();
            final SSLContext sslContext = SSLTestUtils.createClientECSSLContext(opensslClient? "openssl." + protocol : protocol);
            try (SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
                socket.setReuseAddress(true);
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
                byte[] data = new byte[100];
                int read = socket.getInputStream().read(data);

                Assert.assertEquals("hello world", new String(data, 0, read));
                if (!SSL_PROTO_TLSv1_3.equals(protocol)) {
                    Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                }
                Assert.assertEquals(protocol, socket.getSession().getProtocol());
                Assert.assertNotNull(socket.getSession().getCipherSuite());

                Assert.assertNotNull(socket.getSession().getPeerCertificates());
                Assert.assertTrue(socket.getSession().getPeerCertificates().length > 0);
                Assert.assertTrue(socket.getSession().getPeerCertificates()[0] instanceof X509Certificate);
                Assert.assertEquals("CN=localhost", ((X509Certificate) socket.getSession().getPeerCertificates()[0]).getSubjectDN().getName());
                Assert.assertEquals("EC", ((X509Certificate) socket.getSession().getPeerCertificates()[0]).getPublicKey().getAlgorithm());

                Assert.assertNotNull(engineRef.get().getSession().getPeerCertificates());
                Assert.assertTrue(engineRef.get().getSession().getPeerCertificates().length > 0);
                Assert.assertTrue(engineRef.get().getSession().getPeerCertificates()[0] instanceof X509Certificate);
                Assert.assertEquals("CN=Test Client", ((X509Certificate) engineRef.get().getSession().getPeerCertificates()[0]).getSubjectDN().getName());
                Assert.assertEquals("EC", ((X509Certificate) engineRef.get().getSession().getPeerCertificates()[0]).getPublicKey().getAlgorithm());
                socket.getSession().invalidate();
            }
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testTLSv12() throws IOException, NoSuchAlgorithmException, InterruptedException {
        testECCertificates(SSL_PROTO_TLSv1_2, true, true);
        testECCertificates(SSL_PROTO_TLSv1_2, true, false);
        testECCertificates(SSL_PROTO_TLSv1_2, false, true);
    }

    @Test
    public void testTLSv13() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(isTLS13Supported());
        testECCertificates(SSL_PROTO_TLSv1_3, true, true);
        testECCertificates(SSL_PROTO_TLSv1_3, true, false);
        testECCertificates(SSL_PROTO_TLSv1_3, false, true);
    }
}

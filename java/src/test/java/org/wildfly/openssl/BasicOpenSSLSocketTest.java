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
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class BasicOpenSSLSocketTest extends AbstractOpenSSLTest {

    @Test
    public void basicOpenSSLTest1() throws IOException, NoSuchAlgorithmException, InterruptedException {
        basicOpenSSLTest1Base("TLSv1.2");
    }

    @Test
    public void basicOpenSSLTest1TLS13() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(isTLS13Supported());
        basicOpenSSLTest1Base("TLSv1.3");
    }

    private void basicOpenSSLTest1Base(String protocol) throws IOException, NoSuchAlgorithmException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext(protocol), sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(new String[]{protocol}); // only one protocol enabled on server side
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            final SSLContext sslContext = SSLTestUtils.createClientSSLContext("openssl." + protocol);
            try (final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
                socket.setReuseAddress(true);
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
                byte[] data = new byte[100];
                int read = socket.getInputStream().read(data);

                Assert.assertEquals(protocol, socket.getSession().getProtocol());
                Assert.assertEquals(protocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
                Assert.assertEquals("hello world", new String(data, 0, read));
                //TODO: fix client session id
                //Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                socket.getSession().invalidate();
                socket.close();
                serverSocket.close();
                acceptThread.join();
            }
        }

    }

    @Test
    public void basicOpenSSLTest2() throws IOException, NoSuchAlgorithmException, InterruptedException {
        basicOpenSSLTest2Base("TLSv1.2");
    }

    @Test
    public void basicOpenSSLTest2TLS13() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(isTLS13Supported());
        basicOpenSSLTest2Base("TLSv1.3");
    }

    private void basicOpenSSLTest2Base(String protocol) throws IOException, NoSuchAlgorithmException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext(protocol), sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(new String[]{protocol}); // only one protocol enabled on server side
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            final SSLContext sslContext = SSLTestUtils.createClientSSLContext("openssl." + protocol);
            InetSocketAddress socketAddress = (InetSocketAddress) SSLTestUtils.createSocketAddress();
            try (final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket(socketAddress.getAddress(), socketAddress.getPort())) {
                socket.setReuseAddress(true);
                socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
                byte[] data = new byte[100];
                int read = socket.getInputStream().read(data);

                Assert.assertEquals(protocol, socket.getSession().getProtocol());
                Assert.assertEquals(protocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
                Assert.assertEquals("hello world", new String(data, 0, read));
                //TODO: fix client session id
                //Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                socket.getSession().invalidate();
                socket.close();
                serverSocket.close();
                acceptThread.join();
            }
        }
    }
}

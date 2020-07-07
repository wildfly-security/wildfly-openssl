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
import javax.net.ssl.SSLSocket;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class BasicOpenSSLSocketDSATest extends AbstractOpenSSLTest {
    @Before
    public void testOpenSSLVersion() {
        String openSSLVersion = SSL.getInstance().version().split(" ")[1];
        Assume.assumeThat(openSSLVersion.startsWith("1.1."), CoreMatchers.is(false));
    }

    @Test
    public void basicOpenSSLTest1() throws IOException, NoSuchAlgorithmException, InterruptedException {

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, SSLTestUtils.createDSASSLContext("TLSv1.2"), sessionID, engine -> {
                engine.setEnabledCipherSuites(new String[] {"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"});
                return engine;
            }));
            acceptThread.start();
            final SSLContext sslContext = SSLTestUtils.createClientDSASSLContext("openssl.TLSv1.2");
            final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
            socket.setReuseAddress(true);
            socket.setEnabledCipherSuites(new String[] {"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"});
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals("hello world", new String(data, 0, read));
            //TODO: fix client session id
            //Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void basicOpenSSLTest2() throws IOException, NoSuchAlgorithmException, InterruptedException {

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, SSLTestUtils.createDSASSLContext("TLSv1"), sessionID));
            acceptThread.start();
            final SSLContext sslContext = SSLTestUtils.createClientDSASSLContext("openssl.TLSv1");
            InetSocketAddress socketAddress = (InetSocketAddress) SSLTestUtils.createSocketAddress();
            final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket(socketAddress.getAddress(), socketAddress.getPort());
            socket.setReuseAddress(true);
            socket.setEnabledCipherSuites(new String[] {"TLS_DHE_DSS_WITH_AES_128_CBC_SHA"});
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

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

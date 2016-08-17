/*
 * JBoss, Home of Professional Open Source.
 *
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
public class ResumptionSessionTest {

    @Test
    public void testJsse() throws Exception {
        testSessionId(SSLContext.getDefault());
    }

    @Test
    public void testOpenSsl() throws Exception {
        OpenSSLProvider.register();
        testSessionId(SSLTestUtils.createSSLContext("openssl.TLSv1"));
    }

    private void testSessionId(final SSLContext sslContext) throws IOException, InterruptedException {
        final int iterations = 10;
        final Collection<SSLSocket> toClose = new ArrayList<>();

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {

            final Thread acceptThread = new Thread(new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext("TLSv1"), new AtomicReference<>()));
            acceptThread.start();

            byte[] sessionID;
            // Create a connection to get a session ID, all other session id's should match
            try (final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.startHandshake();
                final byte[] id = socket.getSession().getId();
                sessionID = Arrays.copyOf(id, id.length);
            }

            final CountDownLatch latch = new CountDownLatch(iterations);

            for (int i = 0; i < iterations; i++) {
                final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.addHandshakeCompletedListener(new AssertingHandshakeCompletedListener(latch, sessionID));
                socket.startHandshake();
                toClose.add(socket);
            }
            if (!latch.await(10, TimeUnit.SECONDS)) {
                Assert.fail("Failed to complete handshakes");
            }
            // TODO (jrp) remove move
            System.out.println("****** SPACER ******");
            try (final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", 7676));
                socket.startHandshake();
                System.out.println(Arrays.toString(socket.getSession().getId()));
            }
            // TODO (jrp) remove above
            serverSocket.close();
            acceptThread.join(1000);
        } finally {
            for (SSLSocket socket : toClose) {
                try {
                    socket.close();
                } catch (Exception ignore) {
                }
            }
        }

    }

    private static class AssertingHandshakeCompletedListener implements HandshakeCompletedListener {
        private final CountDownLatch latch;
        private final byte[] expectedSessionId;

        private AssertingHandshakeCompletedListener(final CountDownLatch latch, final byte[] expectedSessionId) {
            this.latch = latch;
            this.expectedSessionId = expectedSessionId;
        }

        @Override
        public void handshakeCompleted(final HandshakeCompletedEvent event) {
            latch.countDown();
            System.out.printf("Expected: %s%n", Arrays.toString(expectedSessionId));
            System.out.printf("Found   : %s%n", Arrays.toString(event.getSession().getId()));
            Assert.assertArrayEquals(expectedSessionId, event.getSession().getId());
        }
    }
}

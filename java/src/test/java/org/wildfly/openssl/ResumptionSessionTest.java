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
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
@Ignore
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
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            List<byte[]> sessionIdList = new ArrayList<>();
            final CountDownLatch latch = new CountDownLatch(iterations);

            final Thread acceptThread = new Thread(new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext("TLSv1"), sessionID));
            acceptThread.start();
            for (int i = 0; i < iterations; i++) {
                final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.addHandshakeCompletedListener(new AssertingHandshakeCompletedListener(latch, sessionID));
                socket.startHandshake();
                toClose.add(socket);
                sessionIdList.add(sessionID.get());
            }
            if (!latch.await(10, TimeUnit.SECONDS)) {
                Assert.fail("Failed to complete handshakes");
            }
            for(int i = 1; i < sessionIdList.size(); ++i) {
                Assert.assertArrayEquals(sessionIdList.get(0), sessionIdList.get(i));
            }
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
        private final AtomicReference<byte[]> expectedSessionId;

        private AssertingHandshakeCompletedListener(final CountDownLatch latch, final AtomicReference<byte[]> expectedSessionId) {
            this.latch = latch;
            this.expectedSessionId = expectedSessionId;
        }

        @Override
        public void handshakeCompleted(final HandshakeCompletedEvent event) {
            latch.countDown();
            Assert.assertArrayEquals(expectedSessionId.get(), event.getSession().getId());
        }
    }
}

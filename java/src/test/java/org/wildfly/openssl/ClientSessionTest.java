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

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
public class ClientSessionTest extends AbstractOpenSSLTest {

    private static final byte[] HELLO_WORLD = "hello world".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void testJsse() throws Exception {
        testSessionId(SSLTestUtils.createSSLContext("TLSv1"));
    }

    @Test
    public void testOpenSsl() throws Exception {
        testSessionId(SSLTestUtils.createSSLContext("openssl.TLSv1"));
    }

    @Test
    public void testSessionTimeout() throws Exception {
        final int port1 = SSLTestUtils.PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        try (
                ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port1);
                ServerSocket serverSocket2 = SSLTestUtils.createServerSocket(port2)
        ) {

            final Thread acceptThread1 = startServer(serverSocket1);
            final Thread acceptThread2 = startServer(serverSocket2);

            SSLContext clientContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1");
            final SSLSessionContext clientSession = clientContext.getClientSessionContext();
            byte[] host1SessionId = connectAndWrite(clientContext, port1);
            byte[] host2SessionId = connectAndWrite(clientContext, port2);

            // No timeout was set, id's should be identical
            Assert.assertArrayEquals(host1SessionId, connectAndWrite(clientContext, port1));
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));

            // Set the session timeout to 1 second and sleep for 2 to ensure the timeout works
            clientSession.setSessionTimeout(1);
            TimeUnit.SECONDS.sleep(2L);
            Assert.assertFalse(Arrays.equals(host1SessionId, connectAndWrite(clientContext, port1)));
            Assert.assertFalse(Arrays.equals(host1SessionId, connectAndWrite(clientContext, port2)));

            serverSocket1.close();
            serverSocket2.close();
            acceptThread1.join();
            acceptThread2.join();
        }
    }

    @Test
    public void testSessionInvalidation() throws Exception {
        final int port = SSLTestUtils.PORT;

        try (ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port)) {

            final Thread acceptThread1 = startServer(serverSocket1);
            final FutureSessionId future = new FutureSessionId();
            SSLContext clientContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1");
            try (final SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
                socket.addHandshakeCompletedListener(new FutureHandshakeCompletedListener(future));
                socket.getOutputStream().write(HELLO_WORLD);
                socket.getSession().invalidate();
                socket.getOutputStream().flush();
            }
            byte[] invalided = future.get();
            byte[] newSession = connectAndWrite(clientContext, port);

            Assert.assertFalse(Arrays.equals(invalided, newSession));

            serverSocket1.close();
            acceptThread1.join();
        }
    }

    @Test
    public void testSessionSize() throws Exception {
        final int port1 = SSLTestUtils.PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        try (
                ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port1);
                ServerSocket serverSocket2 = SSLTestUtils.createServerSocket(port2)
        ) {

            final Thread acceptThread1 = startServer(serverSocket1);
            final Thread acceptThread2 = startServer(serverSocket2);
            SSLContext clientContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1");

            final SSLSessionContext clientSession = clientContext.getClientSessionContext();

            byte[] host1SessionId = connectAndWrite(clientContext, port1);
            byte[] host2SessionId = connectAndWrite(clientContext, port2);

            // No cache limit was set, id's should be identical
            Assert.assertArrayEquals(host1SessionId, connectAndWrite(clientContext, port1));
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));

            // Set the cache size to 1
            clientSession.setSessionCacheSize(1);
            // The second session id should be the one kept as it was the last one used
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));
            // Connect again to the first host, this should not match the initial session id for the first host
            byte[] nextId = connectAndWrite(clientContext, port1);
            Assert.assertFalse(Arrays.equals(host1SessionId, nextId));
            // Once more connect to the first host and this should match the previous session id
            Assert.assertArrayEquals(nextId, connectAndWrite(clientContext, port1));
            // Connect to the second host which should be purged at this point
            Assert.assertFalse(Arrays.equals(nextId, connectAndWrite(clientContext, port2)));

            // Reset the cache limit and ensure both sessions are cached
            clientSession.setSessionCacheSize(0);
            host1SessionId = connectAndWrite(clientContext, port1);
            host2SessionId = connectAndWrite(clientContext, port2);

            // No cache limit was set, id's should be identical
            Assert.assertArrayEquals(host1SessionId, connectAndWrite(clientContext, port1));
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));

            serverSocket1.close();
            serverSocket2.close();
            acceptThread1.join();
            acceptThread2.join();
        }
    }


    /**
     * Tests that invalidation of a client session, for whatever reason, when multiple threads
     * are involved in interacting with the server through a SSL socket, doesn't lead to a JVM crash
     *
     * @throws Exception
     */
    @Test
    public void testClientSessionInvalidationMultiThreadAccess() throws Exception {
        final int port = SSLTestUtils.PORT;
        final int numThreads = 10;
        final ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket(port)) {
            final Thread acceptThread = startServer(serverSocket);
            final SSLContext clientContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1.2");
            final List<Future<Void>> taskResults = new ArrayList<>();
            for (int i = 0; i < numThreads; i++) {
                taskResults.add(executor.submit(new SocketWriter(clientContext, SSLTestUtils.HOST, port)));
            }
            // wait for results
            for (int i = 0; i < numThreads; i++) {
                taskResults.get(i).get(10, TimeUnit.SECONDS);
            }
            serverSocket.close();
            acceptThread.join();
        } finally {
            executor.shutdownNow();
        }
    }

    private void testSessionId(final SSLContext sslContext) throws IOException, InterruptedException {
        final int iterations = 10;
        final Collection<SSLSocket> toClose = new ArrayList<>();

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {

            final Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, new AtomicReference<>()));
            acceptThread.start();

            byte[] sessionID;
            // Create a connection to get a session ID, all other session id's should match
            SSLContext clientContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1");
            try (final SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.startHandshake();
                final byte[] id = socket.getSession().getId();
                sessionID = Arrays.copyOf(id, id.length);
            }

            final CountDownLatch latch = new CountDownLatch(iterations);

            for (int i = 0; i < iterations; i++) {
                final SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket();
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.addHandshakeCompletedListener(new AssertingHandshakeCompletedListener(latch, sessionID));
                socket.startHandshake();
                toClose.add(socket);
            }
            if (!latch.await(30, TimeUnit.SECONDS)) {
                Assert.fail("Failed to complete handshakes");
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

    private byte[] connectAndWrite(final SSLContext context, final int port) throws IOException, ExecutionException, InterruptedException {
        final FutureSessionId future = new FutureSessionId();
        try (final SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
            socket.addHandshakeCompletedListener(new FutureHandshakeCompletedListener(future));
            socket.getOutputStream().write(HELLO_WORLD);
            socket.getOutputStream().flush();
        }
        return future.get();
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
            Assert.assertArrayEquals(expectedSessionId, event.getSession().getId());
        }
    }

    private Thread startServer(final ServerSocket serverSocket) throws IOException {
        final Thread acceptThread = new Thread(new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext("TLSv1"), new AtomicReference<>()));
        acceptThread.start();
        return acceptThread;
    }

    private static class FutureHandshakeCompletedListener implements HandshakeCompletedListener {
        private final FutureSessionId futureSessionId;

        private FutureHandshakeCompletedListener(final FutureSessionId futureSessionId) {
            this.futureSessionId = futureSessionId;
        }

        @Override
        public void handshakeCompleted(final HandshakeCompletedEvent event) {
            futureSessionId.value = event.getSession().getId();
        }
    }

    private static class FutureSessionId implements Future<byte[]> {
        private final AtomicBoolean done = new AtomicBoolean(false);
        private volatile byte[] value;

        @Override
        public boolean cancel(final boolean mayInterruptIfRunning) {
            return false;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public boolean isDone() {
            return done.get();
        }

        @Override
        public byte[] get() throws InterruptedException, ExecutionException {
            while (value == null) {
                TimeUnit.MILLISECONDS.sleep(10L);
            }
            done.set(true);
            return value;
        }

        @Override
        public byte[] get(final long timeout, final TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return get();
        }
    }

    private class SocketWriter implements Callable<Void> {
        private final SSLContext sslClientContext;
        private final String host;
        private final int port;

        SocketWriter(final SSLContext sslClientContext, final String host, final int port) {
            this.sslClientContext = sslClientContext;
            this.host = host;
            this.port = port;
        }

        @Override
        public Void call() {
            // create a socket, connect, write some data, invalidate the session
            try (final SSLSocket socket = (SSLSocket) this.sslClientContext.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress(this.host, this.port));
                socket.getOutputStream().write(HELLO_WORLD);
                socket.getOutputStream().flush();
                socket.getSession().invalidate();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return null;
        }
    }
}

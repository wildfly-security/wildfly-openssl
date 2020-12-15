/*
 * JBoss, Home of Professional Open Source.
 *
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import static org.wildfly.openssl.OpenSSLEngine.isTLS13Supported;
import static org.wildfly.openssl.SSLTestUtils.HOST;
import static org.wildfly.openssl.SSLTestUtils.PORT;

import org.junit.Assert;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
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
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ClientSessionTestBase extends AbstractOpenSSLTest {

    private static final byte[] HELLO_WORLD = "hello world".getBytes(StandardCharsets.US_ASCII);

    void testSessionTimeout(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        try (
                ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port1);
                ServerSocket serverSocket2 = SSLTestUtils.createServerSocket(port2)
        ) {

            final Thread acceptThread1 = startServer(serverSocket1, serverProvider);
            final Thread acceptThread2 = startServer(serverSocket2, serverProvider);

            SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
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

    void testSessionTimeoutTLS13(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;
        Server server1 = startServerTLS13(serverProvider, port1);
        Server server2 = startServerTLS13(serverProvider, port2);
        server1.signal();
        server2.signal();
        SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
        SSLSessionContext clientSession = clientContext.getClientSessionContext();
        while (! server1.started || ! server2.started) {
            Thread.yield();
        }
        SSLSession firstSession1 = connect(clientContext, port1);
        Assert.assertFalse(((OpenSSlSession) firstSession1).isReused());
        SSLSession firstSession2 = connect(clientContext, port2);
        Assert.assertFalse(((OpenSSlSession) firstSession2).isReused());
        server1.signal();
        server2.signal();

        // No timeout was set, sessions should be reused
        SSLSession secondSession1 = connect(clientContext, port1);
        Assert.assertTrue(((OpenSSlSession) secondSession1).isReused());
        SSLSession secondSession2 = connect(clientContext, port2);
        Assert.assertTrue(((OpenSSlSession) secondSession2).isReused());
        server1.signal();
        server2.signal();

        // Set the session timeout to 1 second and sleep for 2 to ensure the timeout works
        clientSession.setSessionTimeout(1);
        TimeUnit.SECONDS.sleep(2L);
        SSLSession thirdSession1 = connect(clientContext, port1);
        Assert.assertFalse(((OpenSSlSession) thirdSession1).isReused());
        SSLSession thirdSession2 = connect(clientContext, port2);
        Assert.assertFalse(((OpenSSlSession) thirdSession2).isReused());
        thirdSession1.invalidate();
        thirdSession2.invalidate();
        server1.go = false;
        server1.signal();
        server2.go = false;
        server2.signal();
        while (server1.started || server2.started) {
            Thread.yield();
        }
    }

    void testSessionInvalidation(String serverProvider, String clientProvider) throws Exception {
        final int port = PORT;

        try (ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port)) {

            final Thread acceptThread1 = startServer(serverSocket1, serverProvider);
            final FutureSessionId future = new FutureSessionId();
            SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
            try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
                socket.setReuseAddress(true);
                socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
                socket.addHandshakeCompletedListener(new FutureHandshakeCompletedListener(future));
                socket.getOutputStream().write(HELLO_WORLD);
                socket.getSession().invalidate();
                socket.getOutputStream().flush();
            }
            byte[] invalided = future.get();
            Assert.assertNotNull(invalided);
            byte[] newSession = connectAndWrite(clientContext, port);
            Assert.assertNotNull(newSession);

            Assert.assertFalse(Arrays.equals(invalided, newSession));

            serverSocket1.close();
            acceptThread1.join();
        }
    }

    void testSessionInvalidationTLS13(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;

        Server server = startServerTLS13(serverProvider, port1);
        server.signal();
        SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
        SSLSessionContext clientSession = clientContext.getClientSessionContext();
        while (! server.started) {
            Thread.yield();
        }
        SSLSession firstSession = connect(clientContext, port1);
        server.signal();
        Assert.assertTrue(firstSession.isValid());
        Assert.assertFalse(((OpenSSlSession) firstSession).isReused());
        firstSession.invalidate();
        Assert.assertFalse(firstSession.isValid());
        SSLSession secondSession = connect(clientContext, port1);
        Assert.assertTrue(secondSession.isValid());
        Assert.assertFalse(((OpenSSlSession) secondSession).isReused());
        firstSession.invalidate();
        secondSession.invalidate();
        server.go = false;
        server.signal();
        while (server.started) {
            Thread.yield();
        }
    }

    void testSessionSize(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        try (
                ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port1);
                ServerSocket serverSocket2 = SSLTestUtils.createServerSocket(port2)
        ) {

            final Thread acceptThread1 = startServer(serverSocket1, serverProvider);
            final Thread acceptThread2 = startServer(serverSocket2, serverProvider);
            SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);

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

    void testSessionSizeTLS13(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        Server server1 = startServerTLS13(serverProvider, port1);
        Server server2 = startServerTLS13(serverProvider, port2);
        server1.signal();
        server2.signal();

        SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
        final SSLSessionContext clientSession = clientContext.getClientSessionContext();

        while (! server1.started || ! server2.started) {
            Thread.yield();
        }

        SSLSession host1Session = connect(clientContext, port1);
        Assert.assertFalse(((OpenSSlSession) host1Session).isReused());
        SSLSession host2Session = connect(clientContext, port2);
        Assert.assertFalse(((OpenSSlSession) host2Session).isReused());
        server1.signal();
        server2.signal();

        // No cache limit was set, id's should be identical
        host1Session = connect(clientContext, port1);
        Assert.assertTrue(((OpenSSlSession) host1Session).isReused());
        host2Session = connect(clientContext, port2);
        Assert.assertTrue(((OpenSSlSession) host2Session).isReused());
        server1.signal();
        server2.signal();

        // Set the cache size to 1
        clientSession.setSessionCacheSize(1);
        // The second session should be the one kept as it was the last one used
        host2Session = connect(clientContext, port2);
        Assert.assertTrue(((OpenSSlSession) host2Session).isReused());
        // Connect again to the first host, this should not match the initial session for the first host
        SSLSession nextSession = connect(clientContext, port1);
        Assert.assertFalse(((OpenSSlSession) nextSession).isReused());
        server1.signal();
        server2.signal();

        // Once more connect to the first host and this should match the previous session
        nextSession = connect(clientContext, port1);
        Assert.assertTrue(((OpenSSlSession) nextSession).isReused());
        // Connect to the second host which should be purged at this point
        nextSession = connect(clientContext, port2);
        Assert.assertFalse(((OpenSSlSession) nextSession).isReused());
        server1.signal();
        server2.signal();

        // Reset the cache limit and ensure both sessions are cached
        clientSession.setSessionCacheSize(0);
        host1Session = connect(clientContext, port1);
        Assert.assertFalse(((OpenSSlSession) host1Session).isReused());
        host2Session = connect(clientContext, port2);
        Assert.assertTrue(((OpenSSlSession) host2Session).isReused());
        server1.signal();
        server2.signal();

        // No cache limit was set, id's should be identical
        host1Session = connect(clientContext, port1);
        Assert.assertTrue(((OpenSSlSession) host1Session).isReused());
        host2Session = connect(clientContext, port2);
        Assert.assertTrue(((OpenSSlSession) host2Session).isReused());
        host1Session.invalidate();
        host2Session.invalidate();
        server1.go = false;
        server1.signal();
        server2.go = false;
        server2.signal();

        while (server1.started || server2.started) {
            Thread.yield();
        }
    }

    void testClientSessionInvalidationMultiThreadAccess(String serverProvider, String clientProvider) throws Exception {
        final int port = PORT;
        final int numThreads = 10;
        final ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket(port)) {
            final Thread acceptThread = startServer(serverSocket, serverProvider);
            final SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
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

    void testSessionId(final SSLContext sslContext, final String provider) throws IOException, InterruptedException {
        final int iterations = 10;
        final Collection<SSLSocket> toClose = new ArrayList<>();

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, new AtomicReference<>(), (engine -> {
                try {
                    engine.setEnabledProtocols(new String[]{ "TLSv1.2"});
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            final Thread acceptThread = new Thread(echo);
            acceptThread.start();

            byte[] sessionID;
            // Create a connection to get a session ID, all other session id's should match
            SSLContext clientContext = SSLTestUtils.createClientSSLContext(provider);
            try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
                socket.setReuseAddress(true);
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.startHandshake();
                final byte[] id = socket.getSession().getId();
                sessionID = Arrays.copyOf(id, id.length);
            }

            final CountDownLatch latch = new CountDownLatch(iterations);

            for (int i = 0; i < iterations; i++) {
                final SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket();
                socket.setReuseAddress(true);
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.addHandshakeCompletedListener(new AssertingHandshakeCompletedListener(latch, sessionID, getExpectedProtocolFromProvider(provider)));
                socket.startHandshake();
                toClose.add(socket);
            }
            if (!latch.await(30, TimeUnit.SECONDS)) {
                Assert.fail("Failed to complete handshakes");
            }
            serverSocket.close();
            echo.stop();
            acceptThread.join();
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
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
            socket.setReuseAddress(true);
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
        private final String expectedProtocol;

        private AssertingHandshakeCompletedListener(final CountDownLatch latch, final byte[] expectedSessionId, final String expectedProtocol) {
            this.latch = latch;
            this.expectedSessionId = expectedSessionId;
            this.expectedProtocol = expectedProtocol;
        }

        @Override
        public void handshakeCompleted(final HandshakeCompletedEvent event) {
            latch.countDown();
            Assert.assertArrayEquals(expectedSessionId, event.getSession().getId());
            Assert.assertFalse(CipherSuiteConverter.isTLSv13CipherSuite(event.getCipherSuite()));
            Assert.assertEquals(expectedProtocol, event.getSession().getProtocol());
        }
    }

    private Thread startServer(final ServerSocket serverSocket, final String serverProvider) throws IOException {
        EchoRunnable echo = new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext(serverProvider), new AtomicReference<>(), (engine -> {
            try {
                if (isTLS13Supported()) {
                    engine.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                } else {
                    engine.setEnabledProtocols(new String[]{"TLSv1.2"});
                }
                return engine;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
        final Thread acceptThread = new Thread(echo);
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
            try (SSLSocket socket = (SSLSocket) this.sslClientContext.getSocketFactory().createSocket()) {
                socket.setReuseAddress(true);
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

    private String getExpectedProtocolFromProvider(String provider) {
        if (provider.startsWith("openssl.")) {
            return provider.substring(provider.indexOf(".") + 1);
        } else {
            return provider;
        }
    }

    private static Server startServerTLS13(String provider, int port) {
        Server server = new Server(provider, port);
        new Thread(server).start();
        return server;
    }

    private static class Server implements Runnable {

        public volatile boolean go = true;
        private boolean signal = false;
        public volatile boolean started = false;
        private String provider;
        private int port;

        Server(String provider, int port) {
            this.provider = provider;
            this.port = port;
        }

        private synchronized void waitForSignal() {
            while (!signal) {
                try {
                    wait();
                } catch (InterruptedException ex) {
                    // do nothing
                }
            }
            signal = false;
        }
        public synchronized void signal() {
            signal = true;
            notify();
        }

        @Override
        public void run() {
            try {
                SSLContext serverContext = SSLTestUtils.createSSLContext(provider);
                try (SSLServerSocket sslServerSocket = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(port, 10, InetAddress.getByName(HOST))) {

                    waitForSignal();
                    started = true;
                    while (go) {
                        try {
                            System.out.println("Waiting for connection");
                            Socket sock = sslServerSocket.accept();
                            BufferedReader reader = new BufferedReader(
                                    new InputStreamReader(sock.getInputStream()));
                            String line = reader.readLine();
                            System.out.println("server read: " + line);
                            PrintWriter out = new PrintWriter(
                                    new OutputStreamWriter(sock.getOutputStream()));
                            out.println(line);
                            out.flush();
                            waitForSignal();
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                }
                started = false;
            } catch (Exception ex) {
                started = false;
                throw new RuntimeException(ex);
            }
        }
    }

    private static SSLSession connect(SSLContext sslContext, int port) {

        try {
            SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
            socket.setReuseAddress(true);
            socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
            PrintWriter out = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream()));
            out.println("message");
            out.flush();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            String inMsg = reader.readLine();
            System.out.println("Client received: " + inMsg);
            SSLSession result = socket.getSession();
            socket.close();
            return result;
        } catch (Exception ex) {
            // unexpected exception
            throw new RuntimeException(ex);
        }
    }

}

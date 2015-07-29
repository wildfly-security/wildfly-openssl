/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.undertow.openssl;

import org.eclipse.jetty.alpn.ALPN;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

import static io.undertow.openssl.OpenSSLLogger.ROOT_LOGGER;

public final class OpenSSLEngine extends SSLEngine {

    private static final SSLException ENGINE_CLOSED = ROOT_LOGGER.engineClosed();
    private static final SSLException RENEGOTIATION_UNSUPPORTED = ROOT_LOGGER.renegotiationUnsupported();
    private static final SSLException ENCRYPTED_PACKET_OVERSIZED = ROOT_LOGGER.oversizedPacket();

    private static final Set<String> AVAILABLE_CIPHER_SUITES;

    static {
        final Set<String> availableCipherSuites = new LinkedHashSet<>(128);
        try {
            final long sslCtx = SSL.makeSSLContext(SSL.SSL_PROTOCOL_ALL, SSL.SSL_MODE_SERVER);
            try {
                SSL.setSSLContextOptions(sslCtx, SSL.SSL_OP_ALL);
                SSL.setCipherSuite(sslCtx, "ALL");
                final long ssl = SSL.newSSL(sslCtx, true);
                try {
                    for (String c : SSL.getCiphers(ssl)) {
                        // Filter out bad input.
                        if (c == null || c.length() == 0 || availableCipherSuites.contains(c)) {
                            continue;
                        }
                        availableCipherSuites.add(CipherSuiteConverter.toJava(c, "ALL"));
                    }
                } finally {
                    SSL.freeSSL(ssl);
                }
            } finally {
                SSL.freeSSLContext(sslCtx);
            }
        } catch (Exception e) {
            ROOT_LOGGER.ciphersFailure(e);
        }
        AVAILABLE_CIPHER_SUITES = Collections.unmodifiableSet(availableCipherSuites);
    }

    static {
        ENGINE_CLOSED.setStackTrace(new StackTraceElement[0]);
        RENEGOTIATION_UNSUPPORTED.setStackTrace(new StackTraceElement[0]);
        ENCRYPTED_PACKET_OVERSIZED.setStackTrace(new StackTraceElement[0]);
        DESTROYED_UPDATER = AtomicIntegerFieldUpdater.newUpdater(OpenSSLEngine.class, "destroyed");
    }

    static final int MAX_PLAINTEXT_LENGTH = 16 * 1024; // 2^14
    private static final int MAX_COMPRESSED_LENGTH = MAX_PLAINTEXT_LENGTH + 1024;
    private static final int MAX_CIPHERTEXT_LENGTH = MAX_COMPRESSED_LENGTH + 1024;

    // Protocols
    protected static final int VERIFY_DEPTH = 10;

    private static final String[] SUPPORTED_PROTOCOLS = {
            SSL.SSL_PROTO_SSLv2Hello,
            SSL.SSL_PROTO_SSLv2,
            SSL.SSL_PROTO_SSLv3,
            SSL.SSL_PROTO_TLSv1,
            SSL.SSL_PROTO_TLSv1_1,
            SSL.SSL_PROTO_TLSv1_2
    };
    private static final Set<String> SUPPORTED_PROTOCOLS_SET =
            new HashSet<>(Arrays.asList(SUPPORTED_PROTOCOLS));

    // Header (5) + Data (2^14) + Compression (1024) + Encryption (1024) + MAC (20) + Padding (256)
    static final int MAX_ENCRYPTED_PACKET_LENGTH = MAX_CIPHERTEXT_LENGTH + 5 + 20 + 256;

    public OpenSSLSessionContext getSessionContext() {
        return sessionContext;
    }

    public boolean isClientMode() {
        return clientMode;
    }

    enum ClientAuthMode {
        NONE,
        OPTIONAL,
        REQUIRE,
    }

    private static final AtomicIntegerFieldUpdater<OpenSSLEngine> DESTROYED_UPDATER;

    static final String INVALID_CIPHER = "SSL_NULL_WITH_NULL_NULL";

    private static final long EMPTY_ADDR = SSL.bufferAddress(ByteBuffer.allocate(0));

    // OpenSSL state
    private long ssl;
    private long networkBIO;

    /**
     * 0 - not accepted, 1 - accepted implicitly via wrap()/unwrap(), 2 -
     * accepted explicitly via beginHandshake() call
     */
    private int accepted;
    private boolean alpnRegistered = false;
    private boolean handshakeFinished;
    private boolean receivedShutdown;
    private volatile int destroyed;


    private volatile ClientAuthMode clientAuth = ClientAuthMode.NONE;

    // SSL Engine status variables
    private boolean isInboundDone;
    private boolean isOutboundDone;
    private boolean engineClosed;

    private final boolean clientMode;
    private final OpenSSLSessionContext sessionContext;

    /**
     * Creates a new instance
     *
     * @param sslCtx         an OpenSSL {@code SSL_CTX} object
     *                       engine
     * @param clientMode     {@code true} if this is used for clients, {@code false}
     *                       otherwise
     * @param sessionContext the {@link OpenSSLSessionContext} this
     *                       {@link SSLEngine} belongs to.
     */
    OpenSSLEngine(long sslCtx, String fallbackApplicationProtocol,
                  boolean clientMode, OpenSSLSessionContext sessionContext) {
        if (sslCtx == 0) {
            throw ROOT_LOGGER.noSSLContext();
        }
        ssl = SSL.newSSL(sslCtx, !clientMode);
        networkBIO = SSL.makeNetworkBIO(ssl);
        this.clientMode = clientMode;
        this.sessionContext = sessionContext;
    }

    /**
     * Destroys this engine.
     */
    public synchronized void shutdown() {
        if (DESTROYED_UPDATER.compareAndSet(this, 0, 1)) {
            SSL.freeSSL(ssl);
            SSL.freeBIO(networkBIO);
            sessionContext.removeHandshakeSession(getSsl());
            ssl = networkBIO = 0;

            // internal errors can cause shutdown without marking the engine closed
            isInboundDone = isOutboundDone = engineClosed = true;
        }
    }

    /**
     * Write plaintext data to the OpenSSL internal BIO
     * <p/>
     * Calling this function with src.remaining == 0 is undefined.
     */
    private int writePlaintextData(final ByteBuffer src) {
        final int pos = src.position();
        final int limit = src.limit();
        final int len = Math.min(limit - pos, MAX_PLAINTEXT_LENGTH);
        final int sslWrote;

        if (src.isDirect()) {
            final long addr = SSL.bufferAddress(src) + pos;
            sslWrote = SSL.writeToSSL(ssl, addr, len);
            if (sslWrote > 0) {
                src.position(pos + sslWrote);
                return sslWrote;
            }
        } else {
            ByteBuffer buf = ByteBuffer.allocateDirect(len);
            try {
                final long addr = memoryAddress(buf);

                src.limit(pos + len);

                buf.put(src);
                src.limit(limit);

                sslWrote = SSL.writeToSSL(ssl, addr, len);
                if (sslWrote > 0) {
                    src.position(pos + sslWrote);
                    return sslWrote;
                } else {
                    src.position(pos);
                }
            } finally {
                buf.clear();
                ByteBufferUtils.cleanDirectBuffer(buf);
            }
        }

        throw ROOT_LOGGER.writeToEngineFailed(sslWrote);
    }

    /**
     * Write encrypted data to the OpenSSL network BIO.
     */
    private int writeEncryptedData(final ByteBuffer src) {
        final int pos = src.position();
        final int len = src.remaining();
        if (src.isDirect()) {
            final long addr = SSL.bufferAddress(src) + pos;
            final int netWrote = SSL.writeToBIO(networkBIO, addr, len);
            if (netWrote >= 0) {
                src.position(pos + netWrote);
                return netWrote;
            }
        } else {
            ByteBuffer buf = ByteBuffer.allocateDirect(len);
            try {
                final long addr = memoryAddress(buf);

                buf.put(src);

                final int netWrote = SSL.writeToBIO(networkBIO, addr, len);
                if (netWrote >= 0) {
                    src.position(pos + netWrote);
                    return netWrote;
                } else {
                    src.position(pos);
                }
            } finally {
                buf.clear();
                ByteBufferUtils.cleanDirectBuffer(buf);
            }
        }

        return -1;
    }

    /**
     * Read plaintext data from the OpenSSL internal BIO
     */
    private int readPlaintextData(final ByteBuffer dst) {
        if (dst.isDirect()) {
            final int pos = dst.position();
            final long addr = SSL.bufferAddress(dst) + pos;
            final int len = dst.limit() - pos;
            final int sslRead = SSL.readFromSSL(ssl, addr, len);
            if (sslRead > 0) {
                dst.position(pos + sslRead);
                return sslRead;
            }
        } else {
            final int pos = dst.position();
            final int limit = dst.limit();
            final int len = Math.min(MAX_ENCRYPTED_PACKET_LENGTH, limit - pos);
            final ByteBuffer buf = ByteBuffer.allocateDirect(len);
            try {
                final long addr = memoryAddress(buf);

                final int sslRead = SSL.readFromSSL(ssl, addr, len);
                if (sslRead > 0) {
                    buf.limit(sslRead);
                    dst.limit(pos + sslRead);
                    dst.put(buf);
                    dst.limit(limit);
                    return sslRead;
                }
            } finally {
                buf.clear();
                ByteBufferUtils.cleanDirectBuffer(buf);
            }
        }

        return 0;
    }

    /**
     * Read encrypted data from the OpenSSL network BIO
     */
    private int readEncryptedData(final ByteBuffer dst, final int pending) {
        if (dst.isDirect() && dst.remaining() >= pending) {
            final int pos = dst.position();
            final long addr = SSL.bufferAddress(dst) + pos;
            final int bioRead = SSL.readFromBIO(networkBIO, addr, pending);
            if (bioRead > 0) {
                dst.position(pos + bioRead);
                return bioRead;
            }
        } else {
            final ByteBuffer buf = ByteBuffer.allocateDirect(pending);
            try {
                final long addr = memoryAddress(buf);

                final int bioRead = SSL.readFromBIO(networkBIO, addr, pending);
                if (bioRead > 0) {
                    buf.limit(bioRead);
                    int oldLimit = dst.limit();
                    dst.limit(dst.position() + bioRead);
                    dst.put(buf);
                    dst.limit(oldLimit);
                    return bioRead;
                }
            } finally {
                buf.clear();
                ByteBufferUtils.cleanDirectBuffer(buf);
            }
        }

        return 0;
    }

    @Override
    public synchronized SSLEngineResult wrap(final ByteBuffer[] srcs, final int offset, final int length, final ByteBuffer dst) throws SSLException {

        // Check to make sure the engine has not been closed
        if (destroyed != 0) {
            return new SSLEngineResult(SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }

        // Throw required runtime exceptions
        if (srcs == null) {
            throw ROOT_LOGGER.nullBuffer();
        }
        if (dst == null) {
            throw ROOT_LOGGER.nullBuffer();
        }

        if (offset + length > srcs.length) {
            throw ROOT_LOGGER.invalidBufferIndex(offset, length, srcs.length);
        }

        if (dst.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }

        // Prepare OpenSSL to work in server mode and receive handshake
        if (accepted == 0) {
            beginHandshakeImplicitly();
        }

        // In handshake or close_notify stages, check if call to wrap was made
        // without regard to the handshake status.
        SSLEngineResult.HandshakeStatus handshakeStatus = getHandshakeStatus();

        if ((!handshakeFinished || engineClosed) && handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
            return new SSLEngineResult(getEngineStatus(), SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);
        }

        int bytesProduced = 0;
        int pendingNet;

        // Check for pending data in the network BIO
        pendingNet = SSL.pendingWrittenBytesInBIO(networkBIO);
        if (pendingNet > 0) {
            // Do we have enough room in dst to write encrypted data?
            int capacity = dst.remaining();
            if (capacity < pendingNet) {
                return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, handshakeStatus, 0, bytesProduced);
            }

            // Write the pending data from the network BIO into the dst buffer
            try {
                bytesProduced += readEncryptedData(dst, pendingNet);
            } catch (Exception e) {
                throw new SSLException(e);
            }

            // If isOuboundDone is set, then the data from the network BIO
            // was the close_notify message -- we are not required to wait
            // for the receipt the peer's close_notify message -- shutdown.
            if (isOutboundDone) {
                shutdown();
            }

            return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), 0, bytesProduced);
        }

        // There was no pending data in the network BIO -- encrypt any application data
        int bytesConsumed = 0;
        int endOffset = offset + length;
        for (int i = offset; i < endOffset; ++i) {
            final ByteBuffer src = srcs[i];
            if (src == null) {
                throw ROOT_LOGGER.nullBuffer();
            }
            while (src.hasRemaining()) {

                // Write plaintext application data to the SSL engine
                try {
                    bytesConsumed += writePlaintextData(src);
                } catch (Exception e) {
                    throw new SSLException(e);
                }

                // Check to see if the engine wrote data into the network BIO
                pendingNet = SSL.pendingWrittenBytesInBIO(networkBIO);
                if (pendingNet > 0) {
                    // Do we have enough room in dst to write encrypted data?
                    int capacity = dst.remaining();
                    if (capacity < pendingNet) {
                        return new SSLEngineResult(
                                SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), bytesConsumed, bytesProduced);
                    }

                    // Write the pending data from the network BIO into the dst buffer
                    try {
                        bytesProduced += readEncryptedData(dst, pendingNet);
                    } catch (Exception e) {
                        throw new SSLException(e);
                    }

                    return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), bytesConsumed, bytesProduced);
                }
            }
        }
        return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), bytesConsumed, bytesProduced);
    }

    @Override
    public synchronized SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length) throws SSLException {
        // Check to make sure the engine has not been closed
        if (destroyed != 0) {
            return new SSLEngineResult(SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }

        // Throw requried runtime exceptions
        if (src == null) {
            throw ROOT_LOGGER.nullBuffer();
        }
        if (dsts == null) {
            throw ROOT_LOGGER.nullBuffer();
        }
        if (offset >= dsts.length || offset + length > dsts.length) {
            throw ROOT_LOGGER.invalidBufferIndex(offset, length, dsts.length);
        }

        int capacity = 0;
        final int endOffset = offset + length;
        for (int i = offset; i < endOffset; i++) {
            ByteBuffer dst = dsts[i];
            if (dst == null) {
                throw ROOT_LOGGER.nullBuffer();
            }
            if (dst.isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
            capacity += dst.remaining();
        }

        // Prepare OpenSSL to work in server mode and receive handshake
        if (accepted == 0) {
            beginHandshakeImplicitly();
        }

        // In handshake or close_notify stages, check if call to unwrap was made
        // without regard to the handshake status.
        SSLEngineResult.HandshakeStatus handshakeStatus = getHandshakeStatus();
        if ((!handshakeFinished || engineClosed) && handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            return new SSLEngineResult(getEngineStatus(), SSLEngineResult.HandshakeStatus.NEED_WRAP, 0, 0);
        }

        int len = src.remaining();

        // protect against protocol overflow attack vector
        if (len > MAX_ENCRYPTED_PACKET_LENGTH) {
            isInboundDone = true;
            isOutboundDone = true;
            engineClosed = true;
            shutdown();
            throw ENCRYPTED_PACKET_OVERSIZED;
        }

        // Write encrypted data to network BIO
        int bytesConsumed = -1;
        try {
            int written = writeEncryptedData(src);
            if (written >= 0) {
                if (bytesConsumed == -1) {
                    bytesConsumed = written;
                } else {
                    bytesConsumed += written;
                }
            }
        } catch (Exception e) {
            throw new SSLException(e);
        }
        int lastPrimingReadResult = SSL.readFromSSL(ssl, EMPTY_ADDR, 0); // priming read
        // check if SSL_read returned <= 0. In this case we need to check the error and see if it was something
        // fatal.
        if (lastPrimingReadResult <= 0) {
            // Check for OpenSSL errors caused by the priming read
            long error = SSL.getLastErrorNumber();
            if (error != SSL.SSL_ERROR_NONE) {
                String err = SSL.getErrorString(error);
                ROOT_LOGGER.debugf("Read from SSL failed error: (%s) read result:(%s) error string: %s", error, lastPrimingReadResult, err);
                // There was an internal error -- shutdown
                shutdown();
                throw new SSLException(err);
            }
        }

        if (bytesConsumed < 0) {
            bytesConsumed = 0;
        }

        // There won't be any application data until we're done handshaking
        //
        // We first check handshakeFinished to eliminate the overhead of extra JNI call if possible.
        int pendingApp = (handshakeFinished || SSL.isInInit(ssl) == 0) ? SSL.pendingReadableBytesInSSL(ssl) : 0;
        int bytesProduced = 0;

        if (pendingApp > 0) {
            // Do we have enough room in dsts to write decrypted data?
            if (capacity < pendingApp) {
                return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), bytesConsumed, 0);
            }

            // Write decrypted data to dsts buffers
            int idx = offset;
            while (idx < endOffset) {
                ByteBuffer dst = dsts[idx];
                if (!dst.hasRemaining()) {
                    idx++;
                    continue;
                }

                if (pendingApp <= 0) {
                    break;
                }

                int bytesRead;
                try {
                    bytesRead = readPlaintextData(dst);
                } catch (Exception e) {
                    throw new SSLException(e);
                }

                if (bytesRead == 0) {
                    break;
                }

                bytesProduced += bytesRead;
                pendingApp -= bytesRead;

                if (!dst.hasRemaining()) {
                    idx++;
                }
            }
        }

        // Check to see if we received a close_notify message from the peer
        if (!receivedShutdown && (SSL.getShutdown(ssl) & SSL.SSL_RECEIVED_SHUTDOWN) == SSL.SSL_RECEIVED_SHUTDOWN) {
            receivedShutdown = true;
            closeOutbound();
            closeInbound();
        }
        if (bytesProduced == 0 && bytesConsumed == 0) {
            return new SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, getHandshakeStatus(), bytesConsumed, bytesProduced);
        } else {
            return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), bytesConsumed, bytesProduced);
        }
    }

    @Override
    public Runnable getDelegatedTask() {
        // Currently, we do not delegate SSL computation tasks
        // TODO: in the future, possibly create tasks to do encrypt / decrypt async
        return null;
    }

    @Override
    public synchronized void closeInbound() throws SSLException {
        if (isInboundDone) {
            return;
        }

        isInboundDone = true;
        engineClosed = true;

        shutdown();

        if (accepted != 0 && !receivedShutdown) {
            throw ROOT_LOGGER.inboundClosed();
        }
    }

    @Override
    public synchronized boolean isInboundDone() {
        return isInboundDone || engineClosed;
    }

    @Override
    public synchronized void closeOutbound() {
        if (isOutboundDone) {
            return;
        }

        isOutboundDone = true;
        engineClosed = true;

        if (accepted != 0 && destroyed == 0) {
            int mode = SSL.getShutdown(ssl);
            if ((mode & SSL.SSL_SENT_SHUTDOWN) != SSL.SSL_SENT_SHUTDOWN) {
                SSL.shutdownSSL(ssl);
            }
        } else {
            // engine closing before initial handshake
            shutdown();
        }
    }

    @Override
    public synchronized boolean isOutboundDone() {
        return isOutboundDone;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        Set<String> availableCipherSuites = AVAILABLE_CIPHER_SUITES;
        return availableCipherSuites.toArray(new String[availableCipherSuites.size()]);
    }

    @Override
    public String[] getEnabledCipherSuites() {
        String[] enabled = SSL.getCiphers(ssl);
        if (enabled == null) {
            return new String[0];
        } else {
            for (int i = 0; i < enabled.length; i++) {
                String mapped = toJavaCipherSuite(enabled[i], ssl);
                if (mapped != null) {
                    enabled[i] = mapped;
                }
            }
            return enabled;
        }
    }

    @Override
    public void setEnabledCipherSuites(String[] cipherSuites) {
        if (cipherSuites == null) {
            throw ROOT_LOGGER.nullCypherSuites();
        }
        final StringBuilder buf = new StringBuilder();
        for (String cipherSuite : cipherSuites) {
            if (cipherSuite == null) {
                break;
            }
            String converted = CipherSuiteConverter.toOpenSsl(cipherSuite);
            if (converted != null) {
                cipherSuite = converted;
            }
            if (!AVAILABLE_CIPHER_SUITES.contains(cipherSuite)) {
                ROOT_LOGGER.debugf("Unsupported cypher suite %s(%s), available %s", cipherSuite, converted, AVAILABLE_CIPHER_SUITES);
            }

            buf.append(cipherSuite);
            buf.append(':');
        }

        if (buf.length() == 0) {
            throw ROOT_LOGGER.emptyCypherSuiteList();
        }
        buf.setLength(buf.length() - 1);

        final String cipherSuiteSpec = buf.toString();
        try {
            SSL.setCipherSuites(ssl, cipherSuiteSpec);
        } catch (Exception e) {
            throw ROOT_LOGGER.failedCypherSuite(e, cipherSuiteSpec);
        }
    }

    @Override
    public String[] getSupportedProtocols() {
        return SUPPORTED_PROTOCOLS.clone();
    }

    @Override
    public String[] getEnabledProtocols() {
        List<String> enabled = new ArrayList<>();
        // Seems like there is no way to explict disable SSLv2Hello in openssl so it is always enabled
        enabled.add(SSL.SSL_PROTO_SSLv2Hello);
        int opts = SSL.getOptions(ssl);
        if ((opts & SSL.SSL_OP_NO_TLSv1) == 0) {
            enabled.add(SSL.SSL_PROTO_TLSv1);
        }
        if ((opts & SSL.SSL_OP_NO_TLSv1_1) == 0) {
            enabled.add(SSL.SSL_PROTO_TLSv1_1);
        }
        if ((opts & SSL.SSL_OP_NO_TLSv1_2) == 0) {
            enabled.add(SSL.SSL_PROTO_TLSv1_2);
        }
        if ((opts & SSL.SSL_OP_NO_SSLv2) == 0) {
            enabled.add(SSL.SSL_PROTO_SSLv2);
        }
        if ((opts & SSL.SSL_OP_NO_SSLv3) == 0) {
            enabled.add(SSL.SSL_PROTO_SSLv3);
        }
        int size = enabled.size();
        if (size == 0) {
            return new String[0];
        } else {
            return enabled.toArray(new String[size]);
        }
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            // This is correct from the API docs
            throw new IllegalArgumentException();
        }
        boolean sslv2 = false;
        boolean sslv3 = false;
        boolean tlsv1 = false;
        boolean tlsv1_1 = false;
        boolean tlsv1_2 = false;
        for (String p : protocols) {
            if (!SUPPORTED_PROTOCOLS_SET.contains(p)) {
                throw ROOT_LOGGER.unsupportedProtocol(p);
            }
            if (p.equals(SSL.SSL_PROTO_SSLv2)) {
                sslv2 = true;
            } else if (p.equals(SSL.SSL_PROTO_SSLv3)) {
                sslv3 = true;
            } else if (p.equals(SSL.SSL_PROTO_TLSv1)) {
                tlsv1 = true;
            } else if (p.equals(SSL.SSL_PROTO_TLSv1_1)) {
                tlsv1_1 = true;
            } else if (p.equals(SSL.SSL_PROTO_TLSv1_2)) {
                tlsv1_2 = true;
            }
        }
        // Enable all and then disable what we not want
        SSL.setOptions(ssl, SSL.SSL_OP_ALL);

        if (!sslv2) {
            SSL.setOptions(ssl, SSL.SSL_OP_NO_SSLv2);
        }
        if (!sslv3) {
            SSL.setOptions(ssl, SSL.SSL_OP_NO_SSLv3);
        }
        if (!tlsv1) {
            SSL.setOptions(ssl, SSL.SSL_OP_NO_TLSv1);
        }
        if (!tlsv1_1) {
            SSL.setOptions(ssl, SSL.SSL_OP_NO_TLSv1_1);
        }
        if (!tlsv1_2) {
            SSL.setOptions(ssl, SSL.SSL_OP_NO_TLSv1_2);
        }
    }


    @Override
    public SSLSession getSession() {
        return sessionContext.getSession(SSL.getSessionId(getSsl()));
    }

    @Override
    public synchronized void beginHandshake() throws SSLException {
        if (engineClosed || destroyed != 0) {
            throw ENGINE_CLOSED;
        }
        if (clientMode) {
            switch (accepted) {
                case 0:
                    handshake();
                    accepted = 2;
                    break;
                case 1:
                    // A user did not start handshake by calling this method by him/herself,
                    // but handshake has been started already by wrap() or unwrap() implicitly.
                    // Because it's the user's first time to call this method, it is unfair to
                    // raise an exception.  From the user's standpoint, he or she never asked
                    // for renegotiation.

                    accepted = 2; // Next time this method is invoked by the user, we should raise an exception.
                    break;
                case 2:
                    throw RENEGOTIATION_UNSUPPORTED;
                default:
                    throw new Error();
            }
        } else {
            if (accepted > 0) {
                renegotiate();
            }
            accepted = 2;
        }
    }

    private void beginHandshakeImplicitly() throws SSLException {
        if (engineClosed || destroyed != 0) {
            throw ENGINE_CLOSED;
        }

        if (accepted == 0) {
            handshake();
            accepted = 1;
        }
    }

    private void handshake() throws SSLException {
        if (!alpnRegistered) {
            alpnRegistered = true;
            final ALPN.Provider cb = ALPN.get(this);
            if (cb != null) {
                SSL.setServerALPNCallback(ssl, new ServerALPNCallback() {
                    @Override
                    public String select(String[] data) {
                        ALPN.ServerProvider provider = (ALPN.ServerProvider) ALPN.remove(OpenSSLEngine.this);
                        if (provider != null) {
                            return provider.select(Arrays.asList(data));
                        }
                        return null;
                    }
                });
            }
        }
        int code = SSL.doHandshake(ssl);
        if (code <= 0) {
            // Check for OpenSSL errors caused by the handshake
            long error = SSL.getLastErrorNumber();
            if (error != SSL.SSL_ERROR_NONE) {
                String err = SSL.getErrorString(error);
                ROOT_LOGGER.debugf("Engine handshake failure %s", err);
                // There was an internal error -- shutdown
                shutdown();
                throw new SSLException(err);
            }
        } else {
            // if SSL_do_handshake returns > 0 it means the handshake was finished. This means we can update
            // handshakeFinished directly and so eliminate uncessary calls to SSL.isInInit(...)
            handshakeFinished = true;
        }
    }

    private void renegotiate() throws SSLException {
        handshakeFinished = false;
        int code = SSL.renegotiate(ssl);
        if (code <= 0) {
            // Check for OpenSSL errors caused by the handshake
            long error = SSL.getLastErrorNumber();
            if (error != SSL.SSL_ERROR_NONE) {
                String err = SSL.getErrorString(error);
                ROOT_LOGGER.debugf("Renegotiation failure %s", err);
                // There was an internal error -- shutdown
                shutdown();
                throw new SSLException(err);
            }
        }
    }

    private static long memoryAddress(ByteBuffer buf) {
        return SSL.bufferAddress(buf);
    }

    private SSLEngineResult.Status getEngineStatus() {
        return engineClosed ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        if (accepted == 0 || destroyed != 0) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }

        // Check if we are in the initial handshake phase
        if (!handshakeFinished) {
            // There is pending data in the network BIO -- call wrap
            if (SSL.pendingWrittenBytesInBIO(networkBIO) != 0) {
                return SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }

            // No pending data to be sent to the peer
            // Check to see if we have finished handshaking
            if (SSL.isInInit(ssl) == 0) {
                handshakeFinished = true;
                return SSLEngineResult.HandshakeStatus.FINISHED;
            }

            // No pending data and still handshaking
            // Must be waiting on the peer to send more data
            return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }

        // Check if we are in the shutdown phase
        if (engineClosed) {
            // Waiting to send the close_notify message
            if (SSL.pendingWrittenBytesInBIO(networkBIO) != 0) {
                return SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }

            // Must be waiting to receive the close_notify message
            return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }

        return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    /**
     * Converts the specified OpenSSL cipher suite to the Java cipher suite.
     */
    static String toJavaCipherSuite(String openSslCipherSuite, long ssl) {
        if (openSslCipherSuite == null) {
            return null;
        }

        String prefix = toJavaCipherSuitePrefix(SSL.getVersion(ssl));
        return CipherSuiteConverter.toJava(openSslCipherSuite, prefix);
    }

    /**
     * Converts the protocol version string returned by
     * {@link SSL#getVersion(long)} to protocol family string.
     */
    private static String toJavaCipherSuitePrefix(String protocolVersion) {
        final char c;
        if (protocolVersion == null || protocolVersion.length() == 0) {
            c = 0;
        } else {
            c = protocolVersion.charAt(0);
        }

        switch (c) {
            case 'T':
                return "TLS";
            case 'S':
                return "SSL";
            default:
                return "UNKNOWN";
        }
    }

    @Override
    public void setUseClientMode(boolean clientMode) {
        if (clientMode != this.clientMode) {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public void setNeedClientAuth(boolean b) {
        setClientAuth(b ? ClientAuthMode.REQUIRE : ClientAuthMode.NONE);
    }

    @Override
    public boolean getNeedClientAuth() {
        return clientAuth == ClientAuthMode.REQUIRE;
    }

    @Override
    public void setWantClientAuth(boolean b) {
        setClientAuth(b ? ClientAuthMode.OPTIONAL : ClientAuthMode.NONE);
    }

    @Override
    public boolean getWantClientAuth() {
        return clientAuth == ClientAuthMode.OPTIONAL;
    }

    private void setClientAuth(ClientAuthMode mode) {
        if (clientMode) {
            return;
        }
        synchronized (this) {
            if (clientAuth == mode) {
                // No need to issue any JNI calls if the mode is the same
                return;
            }
            switch (mode) {
                case NONE:
                    SSL.setVerify(ssl, SSL.SSL_CVERIFY_NONE, VERIFY_DEPTH);
                    break;
                case REQUIRE:
                    SSL.setVerify(ssl, SSL.SSL_CVERIFY_REQUIRE, VERIFY_DEPTH);
                    break;
                case OPTIONAL:
                    SSL.setVerify(ssl, SSL.SSL_CVERIFY_OPTIONAL, VERIFY_DEPTH);
                    break;
            }
            clientAuth = mode;
        }
    }

    @Override
    public void setEnableSessionCreation(boolean b) {
        //TODO
        if (b) {
            //throw new UnsupportedOperationException();
        }
    }

    @Override
    public boolean getEnableSessionCreation() {
        return false;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        // Call shutdown as the user may have created the OpenSslEngine and not used it at all.
        shutdown();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return sessionContext.getHandshakeSession(this, SSL.getSessionId(getSsl()));
    }

    long getSsl() {
        return ssl;
    }

    boolean isHandshakeFinished() {
        return handshakeFinished;
    }


}
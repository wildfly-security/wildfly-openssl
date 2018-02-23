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

import static org.wildfly.openssl.Messages.MESSAGES;

import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.wildfly.openssl.DefaultByteBufferPool.PooledByteBuffer;

public final class OpenSSLEngine extends SSLEngine {

    private static final Logger LOG = Logger.getLogger(OpenSSLEngine.class.getName());


    private static final SSLException ENGINE_CLOSED = new SSLException(MESSAGES.engineIsClosed());
    private static final SSLException RENEGOTIATION_UNSUPPORTED = new SSLException(MESSAGES.renegotiationNotSupported());
    private static final SSLException ENCRYPTED_PACKET_OVERSIZED = new SSLException(MESSAGES.oversidedPacket());
    private static final long EMPTY_DIRECT;
    private static final SSL SSL_INSTANCE = SSL.getInstance();

    static {
        ENGINE_CLOSED.setStackTrace(new StackTraceElement[0]);
        RENEGOTIATION_UNSUPPORTED.setStackTrace(new StackTraceElement[0]);
        ENCRYPTED_PACKET_OVERSIZED.setStackTrace(new StackTraceElement[0]);
        DESTROYED_UPDATER = AtomicIntegerFieldUpdater.newUpdater(OpenSSLEngine.class, "destroyed");
		EMPTY_DIRECT = SSL_INSTANCE.bufferAddress(ByteBuffer.allocateDirect(0));
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
    private static final Set<String> SUPPORTED_PROTOCOLS_SET = new HashSet<>(Arrays.asList(SUPPORTED_PROTOCOLS));

    // Header (5) + Data (2^14) + Compression (1024) + Encryption (1024) + MAC (20) + Padding (256)
    static final int MAX_ENCRYPTED_PACKET_LENGTH = MAX_CIPHERTEXT_LENGTH + 5 + 20 + 256;
    public static final int DEFAULT_CERTIFICATE_VALIDATION_DEPTH = 100;

    public OpenSSLSessionContext getSessionContext() {
        if(clientMode) {
            return openSSLContextSPI.engineGetClientSessionContext();
        } else {
            return openSSLContextSPI.engineGetServerSessionContext();
        }
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

    // OpenSSL state
    private final long sslCtx;
    private long ssl = 0;
    private long networkBIO = 0;
    private int serverSelectedCipher = -1;

    private final OpenSSLContextSPI openSSLContextSPI;
    /**
     * 0 - not accepted, 1 - accepted implicitly via wrap()/unwrap(), 2 -
     * accepted explicitly via beginHandshake() call
     */
    private int accepted;
    private boolean alpnRegistered = false;
    private boolean handshakeFinished;
    private boolean receivedShutdown;
    private volatile int destroyed;
    private boolean wantClientAuth = false;
    private boolean needClientAuth = false;


    private volatile ClientAuthMode clientAuth = ClientAuthMode.NONE;

    // SSL Engine status variables
    private boolean isInboundDone;
    private boolean isOutboundDone;
    private boolean engineClosed;

    private boolean clientMode;

    private String[] applicationProtocols;
    private String[] userSetEnabledCipherSuites;
    private String[] userSetEnabledProtocols;
    private String selectedApplicationProtocol;
    private SSLSession handshakeSession;

    private String host;
    private int port;

    private List<Runnable> tasks = new ArrayList<>();

    private int remainingInUnwrapRecord = 0;

	private byte[] sessionId;

    /**
     * Creates a new instance
     *
     * @param sslCtx         an OpenSSL {@code SSL_CTX} object
     *                       engine
     * @param clientMode     {@code true} if this is used for clients, {@code false}
     *                       otherwise
     */
    OpenSSLEngine(long sslCtx,
                  boolean clientMode, OpenSSLContextSPI openSSLContextSPI) {
        this(sslCtx, clientMode, openSSLContextSPI, null, -1);
    }

    OpenSSLEngine(long sslCtx,
                  boolean clientMode, OpenSSLContextSPI openSSLContextSPI, String host, int port) {
        if (sslCtx == 0) {
            throw new IllegalStateException(MESSAGES.noSslContext());
        }
        this.sslCtx = sslCtx;
        this.clientMode = clientMode;
        this.openSSLContextSPI = openSSLContextSPI;
        this.host = host;
        this.port = port;
    }

    void initSsl() {
        if(ssl == 0 && DESTROYED_UPDATER.get(this) == 0) {
			ssl = SSL_INSTANCE.newSSL(sslCtx, !clientMode);
			networkBIO = SSL_INSTANCE.makeNetworkBIO(ssl);
            if(clientMode) {
                openSSLContextSPI.engineGetClientSessionContext().tryAttachClientSideSession(ssl, host, port);
            }
            for(Runnable task : tasks) {
                task.run();
            }
            tasks = null;
        }
    }

    /**
     * Destroys this engine.
     */
    public synchronized void shutdown() {
        if (DESTROYED_UPDATER.compareAndSet(this, 0, 1)) {
            if(ssl != 0) {
				SSL_INSTANCE.shutdownSSL(ssl);
				SSL_INSTANCE.freeSSL(ssl);
				SSL_INSTANCE.freeBIO(networkBIO);
            }
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
        initSsl();
        if (src.isDirect()) {
			sslWrote = SSL_INSTANCE.writeToSSL(ssl, SSL_INSTANCE.bufferAddress(src) + pos, len);
            if (sslWrote > 0) {
                src.position(pos + sslWrote);
                return sslWrote;
            }
        } else {
			try (PooledByteBuffer direct = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
        		ByteBuffer buf = direct.getBuffer();
                src.limit(pos + len);
                buf.put(src);
                src.limit(limit);
				sslWrote = SSL_INSTANCE.writeToSSL(ssl, SSL_INSTANCE.bufferAddress(buf), len);
                if (sslWrote > 0) {
                    src.position(pos + sslWrote);
                    return sslWrote;
                } else {
                    src.position(pos);
                }
            }
        }

        throw new IllegalStateException(MESSAGES.sslWriteFailed(sslWrote));
    }

    /**
     * Write encrypted data to the OpenSSL network BIO.
     */
    private int writeEncryptedData(final ByteBuffer src) {
        final int pos = src.position();
        final int len = src.remaining();
        if (src.isDirect()) {
			final int netWrote = SSL_INSTANCE.writeToBIO(networkBIO, SSL_INSTANCE.bufferAddress(src) + pos, len);
            if (netWrote >= 0) {
                src.position(pos + netWrote);
                return netWrote;
            }
        } else {
        	try (PooledByteBuffer direct = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
        		ByteBuffer buf = direct.getBuffer();
                buf.put(src);
				final int netWrote = SSL_INSTANCE.writeToBIO(networkBIO, SSL_INSTANCE.bufferAddress(buf), len);
                if (netWrote >= 0) {
                    src.position(pos + netWrote);
                    return netWrote;
                } else {
                    src.position(pos);
                }
            }
        }

        return -1;
    }

    /**
     * Read plaintext data from the OpenSSL internal BIO
     */
    private int readPlaintextData(final ByteBuffer dst) throws SSLException {
        initSsl();
        if (dst.isDirect()) {
            final int pos = dst.position();
            final int len = dst.limit() - pos;
			final int sslRead = SSL_INSTANCE.readFromSSL(ssl, SSL_INSTANCE.bufferAddress(dst) + pos, len);
            if (sslRead > 0) {
                dst.position(pos + sslRead);
                return sslRead;
			} else if (sslRead < 0) {
				long error = -sslRead;
				String err = SSL_INSTANCE.getErrorString(error);
                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.fine(MESSAGES.readFromSSLFailed(error, sslRead, err));
                    }
                    // There was an internal error -- shutdown
                    shutdown();
                    throw new SSLException(err);
                }
        } else {
            final int pos = dst.position();
            final int limit = dst.limit();
            final int len = Math.min(MAX_ENCRYPTED_PACKET_LENGTH, limit - pos);
            try (PooledByteBuffer direct = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
            	ByteBuffer buf = direct.getBuffer();
				final int sslRead = SSL_INSTANCE.readFromSSL(ssl, SSL_INSTANCE.bufferAddress(buf), len);
                if (sslRead > 0) {
                    buf.limit(sslRead);
                    dst.limit(pos + sslRead);
                    dst.put(buf);
                    dst.limit(limit);
                    return sslRead;
				} else if (sslRead < 0) {
					long error = -sslRead;
					String err = SSL_INSTANCE.getErrorString(error);
                        if (LOG.isLoggable(Level.FINE)) {
                            LOG.fine(MESSAGES.readFromSSLFailed(error, sslRead, err));
                        }
                        // There was an internal error -- shutdown
                        shutdown();
                        throw new SSLException(err);
                    }
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
			final int bioRead = SSL_INSTANCE.readFromBIO(networkBIO, SSL_INSTANCE.bufferAddress(dst) + pos, pending);
            if (bioRead > 0) {
                dst.position(pos + bioRead);
                return bioRead;
            }
        } else {
        	try (PooledByteBuffer direct = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
        		ByteBuffer buf = direct.getBuffer();
				final int bioRead = SSL_INSTANCE.readFromBIO(networkBIO, SSL_INSTANCE.bufferAddress(buf), pending);
                if (bioRead > 0) {
                    buf.limit(bioRead);
                    int oldLimit = dst.limit();
                    dst.limit(dst.position() + bioRead);
                    dst.put(buf);
                    dst.limit(oldLimit);
                    return bioRead;
                }
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
            throw new IllegalArgumentException(MESSAGES.bufferIsNull());
        }
        if (dst == null) {
            throw new IllegalArgumentException(MESSAGES.bufferIsNull());
        }

        if (offset + length > srcs.length) {
            throw new IndexOutOfBoundsException(MESSAGES.invalidOffset(offset, length, srcs.length));
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
		pendingNet = SSL_INSTANCE.pendingWrittenBytesInBIO(networkBIO);
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
            if(serverSelectedCipher == -1 && !clientMode) {
                ByteBuffer duplicate = dst.duplicate();
                duplicate.flip();
                serverSelectedCipher = OpenSSLServerHelloExplorer.getCipherSuite(duplicate);
				SSL_INSTANCE.saveServerCipher(ssl, serverSelectedCipher);
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
                throw new IllegalArgumentException(MESSAGES.bufferIsNull());
            }
            while (src.hasRemaining()) {

                // Write plaintext application data to the SSL engine
                try {
                    bytesConsumed += writePlaintextData(src);
                } catch (Exception e) {
                    throw new SSLException(e);
                }

                // Check to see if the engine wrote data into the network BIO
				pendingNet = SSL_INSTANCE.pendingWrittenBytesInBIO(networkBIO);
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
                    if(serverSelectedCipher == -1 && !clientMode) {
                        ByteBuffer duplicate = dst.duplicate();
                        duplicate.flip();
                        serverSelectedCipher = OpenSSLServerHelloExplorer.getCipherSuite(duplicate);
						SSL_INSTANCE.saveServerCipher(ssl, serverSelectedCipher);
                    }
                    return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), bytesConsumed, bytesProduced);
                }
            }
        }
        return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), bytesConsumed, bytesProduced);
    }

    @Override
    public synchronized SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length) throws SSLException {
        int consumed = 0, produced = 0;
        for(;;) {
            // Check to make sure the engine has not been closed
            if (destroyed != 0) {
                return new SSLEngineResult(SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
            }
            if (src != null && src.remaining() > 0 && src.remaining() < 5 && remainingInUnwrapRecord == 0) {
                return new SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
            }
            int oldLimit = -1;
            if (src != null && src.remaining() > 0) {
                oldLimit = src.limit();
                if (remainingInUnwrapRecord == 0) {
                    int frameLength = ((src.get(src.position() + 3) & 0xff) << 8) + ((src.get(src.position() + 4)) & 0xff) + 5;
                    remainingInUnwrapRecord = frameLength;
                }
                if (src.remaining() >= remainingInUnwrapRecord) {
                    src.limit(src.position() + remainingInUnwrapRecord);
                }
            }
            try {

                initSsl();

                // Throw required runtime exceptions
                if (src == null) {
                    throw new IllegalArgumentException(MESSAGES.bufferIsNull());
                }
                if (dsts == null) {
                    throw new IllegalArgumentException(MESSAGES.bufferIsNull());
                }
                if (offset >= dsts.length || offset + length > dsts.length) {
                    throw new IndexOutOfBoundsException(MESSAGES.invalidOffset(offset, length, dsts.length));
                }

                int capacity = 0;
                final int endOffset = offset + length;
                for (int i = offset; i < endOffset; i++) {
                    ByteBuffer dst = dsts[i];
                    if (dst == null) {
                        throw new IllegalArgumentException(MESSAGES.bufferIsNull());
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
                try {
                    int written = writeEncryptedData(src);
                    if (written >= 0) {
                        remainingInUnwrapRecord -= written;
                        consumed += written;
                    }
                } catch (Exception e) {
                    throw new SSLException(e);
                }
                int lastPrimingReadResult = SSL_INSTANCE.readFromSSL(ssl, EMPTY_DIRECT, 0); // priming read
                // check if SSL_read returned <= 0. In this case we need to check the error and see if it was something
                // fatal.
				if (lastPrimingReadResult < 0) {
                    // Check for OpenSSL errors caused by the priming read
					long error = -lastPrimingReadResult;
					String err = SSL_INSTANCE.getErrorString(error);
                        if (LOG.isLoggable(Level.FINE)) {
                            LOG.fine(MESSAGES.readFromSSLFailed(error, lastPrimingReadResult, err));
                        }
                        // There was an internal error -- shutdown
                        shutdown();
                        throw new SSLException(err);
                    }

                // There won't be any application data until we're done handshaking
                //
                // We first check handshakeFinished to eliminate the overhead of extra JNI call if possible.
                int pendingApp = (handshakeFinished || SSL_INSTANCE.isInInit(ssl) == 0) ? SSL_INSTANCE.pendingReadableBytesInSSL(ssl) : 0;

                while (pendingApp > 0) {
                    // Do we have enough room in dsts to write decrypted data?
                    if (capacity < pendingApp) {
                        return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, getHandshakeStatus(), consumed, 0);
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

                        produced += bytesRead;
                        pendingApp -= bytesRead;

                        if (!dst.hasRemaining()) {
                            idx++;
                        }
                    }
					pendingApp = SSL_INSTANCE.pendingReadableBytesInSSL(ssl);
                }

                // Check to see if we received a close_notify message from the peer
                if (!receivedShutdown && (SSL_INSTANCE.getShutdown(ssl) & SSL.SSL_RECEIVED_SHUTDOWN) == SSL.SSL_RECEIVED_SHUTDOWN) {
                    receivedShutdown = true;
                    closeOutbound();
                    closeInbound();
                }
            } finally {
                if (oldLimit > 0) {
                    src.limit(oldLimit);
                }
            }
            if (produced == 0 && consumed == 0) {
                return new SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, getHandshakeStatus(), consumed, produced);
            } else if(produced == 0 && consumed > 0 && src.hasRemaining()) {
                //we have consumed a full frame, but produced no output, and there is still more data to consume
                //we attempt to consume the next frame as well
                continue;
            } else {
                return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), consumed, produced);
            }
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
            throw new SSLException(MESSAGES.inboundIsClosed());
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
			int mode = SSL_INSTANCE.getShutdown(ssl);
            if ((mode & SSL.SSL_SENT_SHUTDOWN) != SSL.SSL_SENT_SHUTDOWN) {
				SSL_INSTANCE.shutdownSSL(ssl);
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
        return OpenSSLContextSPI.getAvailableCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        if(ssl == 0) {
            if(userSetEnabledCipherSuites != null) {
                return userSetEnabledCipherSuites;
            } else {
                return openSSLContextSPI.getCiphers();
            }
        }
        initSsl();
		String[] enabled = SSL_INSTANCE.getCiphers(ssl);
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
            throw new IllegalArgumentException(MESSAGES.nullCipherSuites());
        }
        userSetEnabledCipherSuites = cipherSuites;
        Runnable task = () -> {
            final StringBuilder buf = new StringBuilder();
            for (String cipherSuite : cipherSuites) {
                if (cipherSuite == null) {
                    break;
                }
                String converted = CipherSuiteConverter.toOpenSsl(cipherSuite);
                if (converted != null) {
                    cipherSuite = converted;
                }
                Set<String> missing = new HashSet<>();
                Set<String> availbile = new HashSet<>(Arrays.asList(OpenSSLContextSPI.getAvailableCipherSuites()));
                if (!availbile.contains(cipherSuite)) {
                    if (LOG.isLoggable(Level.FINEST)) {
                        missing.add(cipherSuite);
                    }
                }

                if (!missing.isEmpty() && LOG.isLoggable(Level.FINEST)) {
                    LOG.fine("Unsupported cypher suites " + missing + " available " + availbile);
                }

                buf.append(cipherSuite);
                buf.append(':');
            }

            if (buf.length() == 0) {
                throw new IllegalArgumentException(MESSAGES.emptyCipherSuiteList());
            }
            buf.setLength(buf.length() - 1);
            final String cipherSuiteSpec = buf.toString();
            try {
				SSL_INSTANCE.setCipherSuites(ssl, cipherSuiteSpec);
            } catch (Exception e) {
                throw new IllegalStateException(MESSAGES.failedCipherSuite(cipherSuiteSpec), e);
            }
        };
        if(ssl == 0) {
            tasks.add(task);
        } else {
            task.run();
        }
    }

    @Override
    public String[] getSupportedProtocols() {
        return SUPPORTED_PROTOCOLS.clone();
    }

    @Override
    public String[] getEnabledProtocols() {
        if(ssl == 0 && userSetEnabledProtocols != null) {
                return userSetEnabledProtocols;
        }
        List<String> enabled = new ArrayList<>();
        // Seems like there is no way to explict disable SSLv2Hello in openssl so it is always enabled
        enabled.add(SSL.SSL_PROTO_SSLv2Hello);
        int opts;
        if(ssl != 0) {
			opts = SSL_INSTANCE.getOptions(ssl);
        } else {
            opts = openSSLContextSPI.supportedCiphers;
        }
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
        userSetEnabledProtocols = protocols;
        Runnable task = () -> {
            boolean sslv2 = false;
            boolean sslv3 = false;
            boolean tlsv1 = false;
            boolean tlsv1_1 = false;
            boolean tlsv1_2 = false;
            for (String p : protocols) {
                if (!SUPPORTED_PROTOCOLS_SET.contains(p)) {
                    throw new IllegalArgumentException(MESSAGES.unsupportedProtocol(p));
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
			SSL_INSTANCE.setOptions(ssl, SSL.SSL_OP_ALL);

            if (!sslv2) {
				SSL_INSTANCE.setOptions(ssl, SSL.SSL_OP_NO_SSLv2);
            }
            if (!sslv3) {
				SSL_INSTANCE.setOptions(ssl, SSL.SSL_OP_NO_SSLv3);
            }
            if (!tlsv1) {
				SSL_INSTANCE.setOptions(ssl, SSL.SSL_OP_NO_TLSv1);
            }
            if (!tlsv1_1) {
				SSL_INSTANCE.setOptions(ssl, SSL.SSL_OP_NO_TLSv1_1);
            }
            if (!tlsv1_2) {
				SSL_INSTANCE.setOptions(ssl, SSL.SSL_OP_NO_TLSv1_2);
            }
        };
        if(ssl == 0) {
            tasks.add(task);
        } else {
            task.run();
        }
    }


    @Override
    public SSLSession getSession() {
        initSsl();
        if (!handshakeFinished) {
            return getHandshakeSession();
        }
		if (sessionId == null) {
			sessionId = SSL_INSTANCE.getSessionId(getSsl());
		}
		SSLSession session = getSessionContext().getSession(sessionId);
        if(session == null) {
            if(handshakeSession == null) {
                handshakeSession = new OpenSSlSession(!clientMode, getSessionContext());
            }
            return handshakeSession;
        }
        return session;
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
            } else {
            	registerAPLN();
            }
            accepted = 2;
        }
    }

    private void registerAPLN() throws SSLException {
        initSsl();
        if (!alpnRegistered) {
            alpnRegistered = true;
            if (!isClientMode()) {
				SSL_INSTANCE.setServerALPNCallback(ssl, new ServerALPNCallback() {
                    @Override
                    public String select(String[] data) {
						String version = SSL_INSTANCE.getVersion(ssl);
                        if(applicationProtocols == null || version == null || !version.equals("TLSv1.2")) {
                            //only offer ALPN on TLS 1.2, try and force http/1.1 if it is offered, otherwise fail the connection
                            //it seems wrong to hard code protocols in the SSL impl, but openssl does not really allow alpn to be enabled
                            //on a per engine basis
                            for(String i : data) {
                                if(i.equals("http/1.1")) {
                                    return i;
                                }
                            }
                            return null;
                        }

                        for (String proto : applicationProtocols) {
                            for (String clientProto : data) {
                                if (clientProto.equals(proto)) {
                                    selectedApplicationProtocol = proto;
                                    return proto;
                                }
                            }
                        }
                        return null;
                    }
                });
            } else if(applicationProtocols != null){
				SSL_INSTANCE.setAlpnProtos(ssl, applicationProtocols);
            }
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
        initSsl();
        if (!alpnRegistered) {
        	registerAPLN();
        }
		int code = SSL_INSTANCE.doHandshake(ssl);
        if (code <= 0) {
            // Check for OpenSSL errors caused by the handshake
			long error = SSL_INSTANCE.getLastErrorNumber();
            if (error != SSL.SSL_ERROR_NONE) {
				String err = SSL_INSTANCE.getErrorString(error);
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.fine("Engine handshake failure " + err);
                }
                // There was an internal error -- shutdown
                shutdown();
                throw new SSLException(err);
            }
        } else {
            // if SSL_do_handshake returns > 0 it means the handshake was finished. This means we can update
            // handshakeFinished directly and so eliminate uncessary calls to SSL_INSTANCE.isInInit(...)
            handshakeFinished();
        }
    }

    private void handshakeFinished() {
        handshakeFinished = true;
        if(isClientMode() && applicationProtocols != null) {
			selectedApplicationProtocol = SSL_INSTANCE.getAlpnSelected(ssl);
        }
        if(handshakeSession != null) {
			if (this.sessionId == null) {
				sessionId = SSL_INSTANCE.getSessionId(ssl);
			}
            if (handshakeSession != null) {
                getSessionContext().mergeHandshakeSession(handshakeSession, sessionId);
            }
            if (clientMode) {
                openSSLContextSPI.engineGetClientSessionContext().storeClientSideSession(ssl, host, port, sessionId);
            } else {
            	openSSLContextSPI.engineGetServerSessionContext().storeServerSideSession(ssl, sessionId);
            }
        }
    }

    private void renegotiate() throws SSLException {
        initSsl();
        handshakeFinished = false;
		int code = SSL_INSTANCE.renegotiate(ssl);
        if (code <= 0) {
            // Check for OpenSSL errors caused by the handshake
			long error = SSL_INSTANCE.getLastErrorNumber();
            if (error != SSL.SSL_ERROR_NONE) {
				String err = SSL_INSTANCE.getErrorString(error);
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.fine("Renegotiation failure " + err);
                }
                // There was an internal error -- shutdown
                shutdown();
                throw new SSLException(err);
            }
        }
    }

    private SSLEngineResult.Status getEngineStatus() {
        return engineClosed ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK;
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        if (accepted == 0 || destroyed != 0) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        initSsl();

        // Check if we are in the initial handshake phase
        if (!handshakeFinished) {
            // There is pending data in the network BIO -- call wrap
			if (SSL_INSTANCE.pendingWrittenBytesInBIO(networkBIO) != 0) {
                return SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }

            // No pending data to be sent to the peer
            // Check to see if we have finished handshaking
			if (SSL_INSTANCE.isInInit(ssl) == 0) {
                handshakeFinished();
                return SSLEngineResult.HandshakeStatus.FINISHED;
            }

            // No pending data and still handshaking
            // Must be waiting on the peer to send more data
            return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }

        // Check if we are in the shutdown phase
        if (engineClosed) {
            // Waiting to send the close_notify message
			if (SSL_INSTANCE.pendingWrittenBytesInBIO(networkBIO) != 0) {
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

		String prefix = toJavaCipherSuitePrefix(SSL_INSTANCE.getVersion(ssl));
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
        if(ssl == 0) {
            this.clientMode = clientMode;
        } else if (clientMode != this.clientMode) {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public void setNeedClientAuth(boolean b) {
        needClientAuth = b;
        setClientAuth(needClientAuth ? ClientAuthMode.REQUIRE : wantClientAuth ? ClientAuthMode.OPTIONAL : ClientAuthMode.NONE);
    }

    @Override
    public boolean getNeedClientAuth() {
        return clientAuth == ClientAuthMode.REQUIRE;
    }

    @Override
    public void setWantClientAuth(boolean b) {
        wantClientAuth = b;
        setClientAuth(needClientAuth ? ClientAuthMode.REQUIRE : wantClientAuth ? ClientAuthMode.OPTIONAL : ClientAuthMode.NONE);
    }

    @Override
    public boolean getWantClientAuth() {
        return clientAuth == ClientAuthMode.OPTIONAL;
    }

    private void setClientAuth(ClientAuthMode mode) {
        if (clientMode) {
            return;
        }
        if (clientAuth == mode) {
            // No need to issue any JNI calls if the mode is the same
            return;
        }
        clientAuth = mode;
        Runnable task = () -> {
            if (clientMode) {
                return;
            }
            switch (mode) {
                case NONE:
				SSL_INSTANCE.setSSLVerify(ssl, SSL.SSL_CVERIFY_NONE, VERIFY_DEPTH);
                    break;
                case REQUIRE:
				SSL_INSTANCE.setSSLVerify(ssl, SSL.SSL_CVERIFY_REQUIRE, VERIFY_DEPTH);
                    break;
                case OPTIONAL:
				SSL_INSTANCE.setSSLVerify(ssl, SSL.SSL_CVERIFY_OPTIONAL, VERIFY_DEPTH);
                    break;
            }
        };
        if (ssl == 0) {
            tasks.add(task);
        } else {
            task.run();
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
        initSsl();
        if(handshakeFinished) {
            return null;
        }

        if(handshakeSession == null) {
            handshakeSession = new OpenSSlSession(!clientMode, getSessionContext());
        }
        return handshakeSession;
    }

    public String getSelectedApplicationProtocol() {
        return selectedApplicationProtocol;
    }

    public String[] getApplicationProtocols() {
        return applicationProtocols;
    }

    public void setApplicationProtocols(String ... applicationProtocols) {
        this.applicationProtocols = applicationProtocols;
    }

    public static boolean isAlpnSupported() {
		return SSL_INSTANCE.isAlpnSupported();
    }

    long getSsl() {
        initSsl();
        return ssl;
    }

    boolean isHandshakeFinished() {
        return handshakeFinished;
    }

    @Override
    public SSLParameters getSSLParameters() {
        return super.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters sslParameters) {
        super.setSSLParameters(sslParameters);

        Runnable config = () -> {

            // Use server's preference order for ciphers (rather than
            // client's)
            boolean orderCiphersSupported = false;
            try {
				orderCiphersSupported = SSL_INSTANCE.hasOp(SSL.SSL_OP_CIPHER_SERVER_PREFERENCE);
                if (orderCiphersSupported) {
                    if (sslParameters.getUseCipherSuitesOrder()) {
						SSL_INSTANCE.setSSLOptions(ssl, SSL.SSL_OP_CIPHER_SERVER_PREFERENCE);
                    }
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!orderCiphersSupported) {
                // OpenSSL does not support ciphers ordering.
                LOG.fine("The version of SSL in use does not support cipher ordering");
            }

            if(!clientMode) {
                int value = 0;
                if (sslParameters.getNeedClientAuth()) {
                    value = SSL.SSL_CVERIFY_REQUIRE;
                } else if (sslParameters.getWantClientAuth()) {
                    value = SSL.SSL_CVERIFY_OPTIONAL;
                } else {
                    value = SSL.SSL_CVERIFY_NONE;
                }
				SSL_INSTANCE.setSSLVerify(ssl, value, DEFAULT_CERTIFICATE_VALIDATION_DEPTH);
            }
        };
        if(ssl == 0) {
            tasks.add(config);
        } else {
            config.run();
        }

    }

    void setHost(final String host) {
        this.host = host;
    }

    void setPort(final int port) {
        this.port = port;
    }

}

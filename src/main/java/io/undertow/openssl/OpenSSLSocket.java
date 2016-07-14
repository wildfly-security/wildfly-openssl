package io.undertow.openssl;

import static io.undertow.openssl.DefaultByteBufferPool.DIRECT_POOL;
import static io.undertow.openssl.DefaultByteBufferPool.INDIRECT_POOL;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * @author Stuart Douglas
 */
public class OpenSSLSocket extends SSLSocket {

    private final SSLEngine sslEngine;
    private final List<HandshakeCompletedListener> handshakeCompletedListenerList = new ArrayList<>();
    private final OpenSSLOutputStream sslOut;
    private final OpenSSLInputStream sslIn;
    private static final ByteBuffer EMPTY_DIRECT = ByteBuffer.allocateDirect(0);
    private DefaultByteBufferPool.PooledByteBuffer unwrappedData;
    private DefaultByteBufferPool.PooledByteBuffer dataToUnwrap;

    private boolean handshakeDone = false;

    protected OpenSSLSocket(SSLEngine sslEngine) {
        super();
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
    }

    protected OpenSSLSocket(String host, int port, SSLEngine sslEngine) throws IOException, UnknownHostException {
        super(host, port);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
    }

    protected OpenSSLSocket(InetAddress address, int port, SSLEngine sslEngine) throws IOException {
        super(address, port);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
    }

    protected OpenSSLSocket(String host, int port, InetAddress clientAddress, int clientPort, SSLEngine sslEngine) throws IOException, UnknownHostException {
        super(host, port, clientAddress, clientPort);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
    }

    protected OpenSSLSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, SSLEngine sslEngine) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
    }

    @Override
    public SSLSession getHandshakeSession() {
        return sslEngine.getHandshakeSession();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return sslEngine.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        sslEngine.setSSLParameters(params);
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return sslIn;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return sslOut;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslEngine.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return sslEngine.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslEngine.setEnabledProtocols(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return sslEngine.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return sslEngine.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslEngine.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return sslEngine.getSession();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListenerList.add(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListenerList.remove(listener);
    }

    @Override
    public void startHandshake() throws IOException {
        handshakeDone = false;
        sslEngine.beginHandshake();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        sslEngine.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return sslEngine.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslEngine.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslEngine.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslEngine.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return sslEngine.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslEngine.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslEngine.getEnableSessionCreation();
    }

    private void invokeHandshakeListeners() {
        final HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, getSession());
        for (HandshakeCompletedListener listener : new ArrayList<>(handshakeCompletedListenerList)) {
            listener.handshakeCompleted(event);
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (unwrappedData != null) {
            unwrappedData.close();
            unwrappedData = null;
        }
        if (dataToUnwrap != null) {
            dataToUnwrap.close();
            dataToUnwrap = null;
        }
        super.close();
    }

    private void runHandshake() throws IOException {
        if (handshakeDone) {
            return;
        }
        try (DefaultByteBufferPool.PooledByteBuffer directPooled = DefaultByteBufferPool.DIRECT_POOL.allocate()) {

            ByteBuffer buffer = directPooled.getBuffer();
            //if we are the client we write first
            boolean write = sslEngine.getUseClientMode();
            for (; ; ) {
                SSLEngineResult result;
                if (write) {
                    buffer.clear();
                    result = sslEngine.wrap(EMPTY_DIRECT, buffer);
                    if (result.bytesProduced() > 0) {
                        buffer.flip();
                        try (DefaultByteBufferPool.PooledByteBuffer indirectPooled = INDIRECT_POOL.allocate()) {
                            indirectPooled.getBuffer().put(buffer);
                            indirectPooled.getBuffer().flip();
                            super.getOutputStream().write(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
                        }
                    }
                } else {
                    try (DefaultByteBufferPool.PooledByteBuffer indirectPooled = INDIRECT_POOL.allocate()) {
                        int readOffset = 0;
                        for (; ; ) {
                            int read = super.getInputStream().read(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset() + readOffset, indirectPooled.getBuffer().remaining());
                            readOffset += read;
                            if (read > 0) {
                                indirectPooled.getBuffer().limit(readOffset);
                                if (unwrappedData != null) {
                                    throw new IllegalStateException("Running handshake with buffered unwrapped data");
                                }
                                unwrappedData = DIRECT_POOL.allocate();
                                buffer.clear();
                                buffer.put(indirectPooled.getBuffer());
                                buffer.flip();
                                result = sslEngine.unwrap(buffer, unwrappedData.getBuffer());
                                if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                    //try and read some more from the socket
                                    continue;
                                }
                                if (unwrappedData.getBuffer().position() == 0) {
                                    unwrappedData.close();
                                    unwrappedData = null;
                                }
                                break;
                            } else {
                                close();
                                throw new SSLException("handshake failed: underlying connection was closed");
                            }
                        }
                    }
                }
                if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                    handshakeDone = true;
                    invokeHandshakeListeners();
                    return;
                } else if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    Runnable r;
                    while ((r = sslEngine.getDelegatedTask()) != null) {
                        r.run();
                    }
                    write = true; //we assume a write after need_task, as it is the only safe option
                } else if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    write = false;
                } else {
                    write = true;
                }

            }
        }

    }

    public int read() throws IOException {
        byte[] b = new byte[1];
        read(b);
        return b[0] & 0xFF;
    }

    public int read(byte[] b, int off, int len) throws IOException {
        if (unwrappedData != null) {
            ByteBuffer buf = unwrappedData.getBuffer();
            int oldLimit = buf.limit();
            int read = buf.remaining();
            if (len < buf.remaining()) {
                buf.limit(buf.position() + len);
                read = len;
            }
            buf.get(b, off, len);
            buf.limit(oldLimit);
            if (!buf.hasRemaining()) {
                unwrappedData.close();
                unwrappedData = null;
            }
            return read;
        }
        runHandshake();

        try (DefaultByteBufferPool.PooledByteBuffer pooled = DIRECT_POOL.allocate()) {
            ByteBuffer buffer = pooled.getBuffer();
            int readOffset = 0;
            DefaultByteBufferPool.PooledByteBuffer indirectPooled;
            if (dataToUnwrap != null) {
                indirectPooled = dataToUnwrap;
                dataToUnwrap = null;
                readOffset = indirectPooled.getBuffer().limit();
            } else {
                indirectPooled = INDIRECT_POOL.allocate();
            }
            boolean freeIndirect = true;
            try {
                unwrappedData = DIRECT_POOL.allocate();
                for (; ; ) {
                    int read = super.getInputStream().read(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset() + readOffset, indirectPooled.getBuffer().remaining());
                    readOffset += read;
                    if (read > 0) {
                        indirectPooled.getBuffer().limit(readOffset);
                        if (unwrappedData != null) {
                            throw new IllegalStateException("Running handshake with buffered unwrapped data");
                        }
                        buffer.clear();
                        buffer.put(indirectPooled.getBuffer());
                        buffer.flip();
                        SSLEngineResult result = sslEngine.unwrap(buffer, unwrappedData.getBuffer());
                        if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                            //try and read some more from the socket
                            continue;
                        }
                        if(result.bytesProduced() == 0) {
                            continue;
                        }
                        int ret = Math.min(len, unwrappedData.getBuffer().remaining());
                        unwrappedData.getBuffer().get(b, off, read);
                        if(buffer.hasRemaining()) {
                            freeIndirect = false;
                            indirectPooled.getBuffer().clear();
                            indirectPooled.getBuffer().put(buffer);
                        }

                        return ret;
                    } else {
                        close();
                        throw new SSLException("handshake failed: underlying connection was closed");
                    }
                }
            } catch (IOException | RuntimeException e) {
                if (unwrappedData != null) {
                    unwrappedData.close();
                    unwrappedData = null;
                }
                throw e;
            } finally {
                if (freeIndirect) {
                    indirectPooled.close();
                }
                if (unwrappedData.getBuffer().position() == 0) {
                    unwrappedData.close();
                    unwrappedData = null;
                }
            }
        }
    }

    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    public void write(int b) throws IOException {
        byte[] data = new byte[1];
        data[0] = (byte) (b & 0xFF);
        write(data);
    }

    public void flush() throws IOException {
        getOutputStream().flush();
    }

    public void write(byte[] b, int off, int len) throws IOException {
        runHandshake();
        try (DefaultByteBufferPool.PooledByteBuffer uncompressedPooled = DIRECT_POOL.allocate()) {
            try (DefaultByteBufferPool.PooledByteBuffer compressedPooled = DIRECT_POOL.allocate()) {
                try (DefaultByteBufferPool.PooledByteBuffer indirectPooled = INDIRECT_POOL.allocate()) {
                    int written = 0;
                    for (; ; ) {
                        ByteBuffer buf = uncompressedPooled.getBuffer();
                        buf.clear();
                        int toWrite = len - written;
                        buf.put(b, off + written, Math.min(toWrite, buf.remaining()));
                        buf.flip();
                        while (buf.hasRemaining()) {
                            compressedPooled.getBuffer().clear();
                            SSLEngineResult result = sslEngine.wrap(buf, compressedPooled.getBuffer());
                            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                                close();
                                throw new IOException("Buffer overflow");//should never happen
                            } else if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                close();
                                throw new IOException("Buffer underflow");//should never happen
                            }
                            int produced = result.bytesProduced();
                            if (produced > 0) {
                                indirectPooled.getBuffer().clear();
                                indirectPooled.getBuffer().put(compressedPooled.getBuffer());
                                indirectPooled.getBuffer().flip();
                                super.getOutputStream().write(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset(), indirectPooled.getBuffer().limit());
                            }
                        }
                    }
                }
            }
        }

    }

    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }
}

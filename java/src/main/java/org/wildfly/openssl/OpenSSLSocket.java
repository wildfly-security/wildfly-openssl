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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * @author Stuart Douglas
 */
public class OpenSSLSocket extends SSLSocket {

    private final OpenSSLEngine sslEngine;
    private final List<HandshakeCompletedListener> handshakeCompletedListenerList = new ArrayList<>();
    private final OpenSSLOutputStream sslOut;
    private final OpenSSLInputStream sslIn;
    private static final ByteBuffer EMPTY_DIRECT = ByteBuffer.allocateDirect(0);
    private DefaultByteBufferPool.PooledByteBuffer unwrappedData;
    private DefaultByteBufferPool.PooledByteBuffer dataToUnwrap;

    private boolean handshakeDone = false;

    private final Socket delegate;

    private final boolean autoclose;

    protected OpenSSLSocket(OpenSSLEngine sslEngine) {
        super();
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = this;
        this.autoclose = true;
    }

    protected OpenSSLSocket(String host, int port, OpenSSLEngine sslEngine) throws IOException, UnknownHostException {
        super(host, port);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = this;
        this.autoclose = true;
        sslEngine.setHost(host);
        sslEngine.setPort(port);
    }

    protected OpenSSLSocket(InetAddress address, int port, OpenSSLEngine sslEngine) throws IOException {
        super(address, port);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = this;
        this.autoclose = true;
        sslEngine.setHost(address.getHostAddress());
        sslEngine.setPort(port);
    }

    protected OpenSSLSocket(String host, int port, InetAddress clientAddress, int clientPort, OpenSSLEngine sslEngine) throws IOException, UnknownHostException {
        super(host, port, clientAddress, clientPort);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = this;
        this.autoclose = true;
        sslEngine.setHost(host);
        sslEngine.setPort(port);

    }

    protected OpenSSLSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, OpenSSLEngine sslEngine) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = this;
        this.autoclose = true;
        sslEngine.setHost(address.getHostAddress());
        sslEngine.setPort(port);
    }

    protected OpenSSLSocket(Socket socket, boolean autoclose, OpenSSLEngine sslEngine) {
        super();
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        this.delegate = socket;
        this.autoclose = autoclose;
    }

    protected OpenSSLSocket(Socket socket, boolean autoclose, String host, int port, OpenSSLEngine sslEngine) throws IOException, UnknownHostException {
        super(host, port);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        this.delegate = socket;
        this.autoclose = autoclose;
        sslEngine.setHost(host);
        sslEngine.setPort(port);
    }

    protected OpenSSLSocket(Socket socket, boolean autoclose, InetAddress address, int port, OpenSSLEngine sslEngine) throws IOException {
        super(address, port);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        this.delegate = socket;
        this.autoclose = autoclose;
        sslEngine.setHost(address.getHostAddress());
        sslEngine.setPort(port);
    }

    protected OpenSSLSocket(Socket socket, boolean autoclose, String host, int port, InetAddress clientAddress, int clientPort, OpenSSLEngine sslEngine) throws IOException, UnknownHostException {
        super(host, port, clientAddress, clientPort);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        this.delegate = socket;
        this.autoclose = autoclose;
        sslEngine.setHost(host);
        sslEngine.setPort(port);
    }

    protected OpenSSLSocket(Socket socket, boolean autoclose, InetAddress address, int port, InetAddress clientAddress, int clientPort, OpenSSLEngine sslEngine) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        this.delegate = socket;
        this.autoclose = autoclose;
        sslEngine.setHost(address.getHostAddress());
        sslEngine.setPort(port);
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
        runHandshake();
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
        if (delegate == this) {
            super.close();
        } else if (autoclose) {
            delegate.close();
        }
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
                        try (DefaultByteBufferPool.PooledByteBuffer indirectPooled = DefaultByteBufferPool.INDIRECT_POOL.allocate()) {
                            ByteBuffer ind = indirectPooled.getBuffer();
                            ind.put(buffer);
                            ind.flip();
                            getDelegateOutputStream().write(ind.array(), ind.arrayOffset() + ind.position(), ind.remaining());
                        }
                    }
                } else {
                    try (DefaultByteBufferPool.PooledByteBuffer indirectPooled = DefaultByteBufferPool.INDIRECT_POOL.allocate()) {
                        int readOffset = 0;
                        for (; ; ) {
                            int read = getDelegateInputStream().read(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset() + readOffset, indirectPooled.getBuffer().remaining());
                            readOffset += read;
                            if (read > 0) {
                                indirectPooled.getBuffer().limit(readOffset);
                                if (unwrappedData != null) {
                                    throw new IllegalStateException("Running handshake with buffered unwrapped data");
                                }
                                unwrappedData = DefaultByteBufferPool.DIRECT_POOL.allocate();
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

    private InputStream getDelegateInputStream() throws IOException {
        if (delegate == this) {
            return super.getInputStream();
        }
        return delegate.getInputStream();
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

        try (DefaultByteBufferPool.PooledByteBuffer pooled = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
            ByteBuffer buffer = pooled.getBuffer();
            int readOffset = 0;
            DefaultByteBufferPool.PooledByteBuffer indirectPooled;
            if (dataToUnwrap != null) {
                indirectPooled = dataToUnwrap;
                dataToUnwrap = null;
                readOffset = indirectPooled.getBuffer().limit();
            } else {
                indirectPooled = DefaultByteBufferPool.INDIRECT_POOL.allocate();
            }
            boolean freeIndirect = true;
            try {
                unwrappedData = DefaultByteBufferPool.DIRECT_POOL.allocate();
                for (; ; ) {
                    int read = getDelegateInputStream().read(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset() + readOffset, indirectPooled.getBuffer().remaining());
                    readOffset += read;
                    if (readOffset > 0) {
                        indirectPooled.getBuffer().limit(readOffset);
                        buffer.clear();
                        buffer.put(indirectPooled.getBuffer());
                        buffer.flip();
                        SSLEngineResult result = sslEngine.unwrap(buffer, unwrappedData.getBuffer());
                        unwrappedData.getBuffer().flip();
                        if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                            //try and read some more from the socket
                            continue;
                        }
                        if (result.bytesProduced() == 0) {
                            continue;
                        }
                        int ret = Math.min(len, unwrappedData.getBuffer().remaining());
                        unwrappedData.getBuffer().get(b, off, ret);
                        if (buffer.hasRemaining()) {
                            freeIndirect = false;
                            indirectPooled.getBuffer().clear();
                            indirectPooled.getBuffer().put(buffer);
                            dataToUnwrap = indirectPooled;
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
                if (unwrappedData != null && unwrappedData.getBuffer().position() == 0) {
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
        getDelegateOutputStream().flush();
    }

    public void write(byte[] b, int off, int len) throws IOException {
        runHandshake();
        try (DefaultByteBufferPool.PooledByteBuffer uncompressedPooled = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
            try (DefaultByteBufferPool.PooledByteBuffer compressedPooled = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
                try (DefaultByteBufferPool.PooledByteBuffer indirectPooled = DefaultByteBufferPool.INDIRECT_POOL.allocate()) {
                    int written = 0;
                    ByteBuffer buf = uncompressedPooled.getBuffer();
                    buf.clear();
                    int toWrite = len - written;
                    buf.put(b, off + written, Math.min(toWrite, buf.remaining()));
                    buf.flip();
                    while (buf.hasRemaining()) {
                        compressedPooled.getBuffer().clear();
                        SSLEngineResult result = sslEngine.wrap(buf, compressedPooled.getBuffer());
                        compressedPooled.getBuffer().flip();
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
                            getDelegateOutputStream().write(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset() + indirectPooled.getBuffer().position(), indirectPooled.getBuffer().remaining());
                        }
                    }
                }
            }
        }

    }

    private OutputStream getDelegateOutputStream() throws IOException {
        if (delegate == this) {
            return super.getOutputStream();
        }
        return delegate.getOutputStream();
    }

    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }


    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        if (delegate == this) {
            super.connect(endpoint);
        } else {
            delegate.connect(endpoint);
        }

        if (!(endpoint instanceof InetSocketAddress))
            throw new IllegalArgumentException("Unsupported address type");
        final InetSocketAddress address = (InetSocketAddress) endpoint;
        sslEngine.setHost(address.getHostName());
        sslEngine.setPort(address.getPort());
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (delegate == this) {
            super.connect(endpoint, timeout);
        } else {
            delegate.connect(endpoint, timeout);
        }

        if (!(endpoint instanceof InetSocketAddress))
            throw new IllegalArgumentException("Unsupported address type");
        final InetSocketAddress address = (InetSocketAddress) endpoint;
        sslEngine.setHost(address.getHostName());
        sslEngine.setPort(address.getPort());
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        if (delegate == this) {
            super.bind(bindpoint);
        } else {
            delegate.bind(bindpoint);
        }
    }

    @Override
    public InetAddress getInetAddress() {
        if (delegate == this) {
            return super.getInetAddress();
        } else {
            return delegate.getInetAddress();
        }
    }

    @Override
    public InetAddress getLocalAddress() {
        if (delegate == this) {
            return super.getLocalAddress();
        } else {
            return delegate.getLocalAddress();
        }
    }

    @Override
    public int getPort() {
        if (delegate == this) {
            return super.getPort();
        } else {
            return delegate.getPort();
        }
    }

    @Override
    public int getLocalPort() {
        if (delegate == this) {
            return super.getLocalPort();
        } else {
            return delegate.getLocalPort();
        }
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        if (delegate == this) {
            return super.getRemoteSocketAddress();
        } else {
            return delegate.getRemoteSocketAddress();
        }
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        if (delegate == this) {
            return super.getLocalSocketAddress();
        } else {
            return delegate.getLocalSocketAddress();
        }
    }

    @Override
    public SocketChannel getChannel() {
        if (delegate == this) {
            return super.getChannel();
        } else {
            return delegate.getChannel();
        }
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        if (delegate == this) {
            super.setTcpNoDelay(on);
        } else {
            delegate.setTcpNoDelay(on);
        }
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        if (delegate == this) {
            return super.getTcpNoDelay();
        } else {
            return delegate.getTcpNoDelay();
        }
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        if (delegate == this) {
            super.setSoLinger(on, linger);
        } else {
            delegate.setSoLinger(on, linger);
        }
    }

    @Override
    public int getSoLinger() throws SocketException {
        if (delegate == this) {
            return super.getSoLinger();
        } else {
            return delegate.getSoLinger();
        }
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        if (delegate == this) {
            super.sendUrgentData(data);
        } else {
            delegate.sendUrgentData(data);
        }
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        if (delegate == this) {
            super.setOOBInline(on);
        } else {
            delegate.setOOBInline(on);
        }
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        if (delegate == this) {
            return super.getOOBInline();
        } else {
            return delegate.getOOBInline();
        }
    }

    @Override
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        if (delegate == this) {
            super.setSoTimeout(timeout);
        } else {
            delegate.setSoTimeout(timeout);
        }
    }

    @Override
    public synchronized int getSoTimeout() throws SocketException {
        if (delegate == this) {
            return super.getSoTimeout();
        } else {
            return delegate.getSoTimeout();
        }
    }

    @Override
    public synchronized void setSendBufferSize(int size) throws SocketException {
        if (delegate == this) {
            super.setSendBufferSize(size);
        } else {
            delegate.setSendBufferSize(size);
        }
    }

    @Override
    public synchronized int getSendBufferSize() throws SocketException {
        if (delegate == this) {
            return super.getSendBufferSize();
        } else {
            return delegate.getSendBufferSize();
        }
    }

    @Override
    public synchronized void setReceiveBufferSize(int size) throws SocketException {
        if (delegate == this) {
            super.setReceiveBufferSize(size);
        } else {
            delegate.setReceiveBufferSize(size);
        }
    }

    @Override
    public synchronized int getReceiveBufferSize() throws SocketException {
        if (delegate == this) {
            return super.getReceiveBufferSize();
        } else {
            return delegate.getReceiveBufferSize();
        }
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        if (delegate == this) {
            super.setKeepAlive(on);
        } else {
            delegate.setKeepAlive(on);
        }
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        if (delegate == this) {
            return super.getKeepAlive();
        } else {
            return delegate.getKeepAlive();
        }
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        if (delegate == this) {
            super.setTrafficClass(tc);
        } else {
            delegate.setTrafficClass(tc);
        }
    }

    @Override
    public int getTrafficClass() throws SocketException {
        if (delegate == this) {
            return super.getTrafficClass();
        } else {
            return delegate.getTrafficClass();
        }
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        if (delegate == this) {
            super.setReuseAddress(on);
        } else {
            delegate.setReuseAddress(on);
        }
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        if (delegate == this) {
            return super.getReuseAddress();
        } else {
            return delegate.getReuseAddress();
        }
    }

    @Override
    public void shutdownInput() throws IOException {
        if (delegate == this) {
            super.shutdownInput();
        } else {
            delegate.shutdownInput();
        }
    }

    @Override
    public void shutdownOutput() throws IOException {
        if (delegate == this) {
            super.shutdownOutput();
        } else {
            delegate.shutdownOutput();
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " ]engine state: " + sslEngine + "]";
    }

    @Override
    public boolean isConnected() {
        if (delegate == this) {
            return super.isConnected();
        } else {
            return delegate.isConnected();
        }
    }

    @Override
    public boolean isBound() {
        if (delegate == this) {
            return super.isBound();
        } else {
            return delegate.isBound();
        }
    }

    @Override
    public boolean isClosed() {
        if (delegate == this) {
            return super.isClosed();
        } else {
            return delegate.isClosed();
        }
    }

    @Override
    public boolean isInputShutdown() {
        if (delegate == this) {
            return super.isInputShutdown();
        } else {
            return delegate.isInputShutdown();
        }
    }

    @Override
    public boolean isOutputShutdown() {
        if (delegate == this) {
            return super.isOutputShutdown();
        } else {
            return delegate.isOutputShutdown();
        }
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        if (delegate == this) {
            super.setPerformancePreferences(connectionTime, latency, bandwidth);
        } else {
            delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
        }
    }

    public String getSelectedApplicationProtocol() {
        return sslEngine.getSelectedApplicationProtocol();
    }

    public String[] getApplicationProtocols() {
        return sslEngine.getApplicationProtocols();
    }

    public void setApplicationProtocols(String... applicationProtocols) {
        sslEngine.setApplicationProtocols(applicationProtocols);
    }

}

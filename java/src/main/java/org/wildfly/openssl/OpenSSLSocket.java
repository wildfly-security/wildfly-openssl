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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    private static final Logger logger = Logger.getLogger(OpenSSLSocket.class.getName());

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
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = null;
        this.autoclose = true;
    }

    protected OpenSSLSocket(String host, int port, OpenSSLEngine sslEngine) throws IOException {
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = null;
        this.autoclose = true;
        sslEngine.setHost(host);
        sslEngine.setPort(port);
        connect(new InetSocketAddress(host, port));
    }

    protected OpenSSLSocket(InetAddress address, int port, OpenSSLEngine sslEngine) throws IOException {
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = null;
        this.autoclose = true;
        sslEngine.setHost(address.getHostName());
        sslEngine.setPort(port);
        connect(new InetSocketAddress(address, port));
    }

    protected OpenSSLSocket(String host, int port, InetAddress clientAddress, int clientPort, OpenSSLEngine sslEngine) throws IOException {
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = null;
        this.autoclose = true;
        sslEngine.setHost(host);
        sslEngine.setPort(port);
        bind(new InetSocketAddress(clientAddress, clientPort));
        connect(new InetSocketAddress(host, port));

    }

    protected OpenSSLSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, OpenSSLEngine sslEngine) throws IOException {
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        delegate = null;
        this.autoclose = true;
        sslEngine.setHost(address.getHostName());
        sslEngine.setPort(port);
        bind(new InetSocketAddress(clientAddress, clientPort));
        connect(new InetSocketAddress(address, port));
    }

    protected OpenSSLSocket(Socket socket, boolean autoclose, OpenSSLEngine sslEngine) {
        super();
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        this.delegate = socket;
        this.autoclose = autoclose;
    }

    protected OpenSSLSocket(Socket socket, boolean autoclose, String host, int port, OpenSSLEngine sslEngine) throws IOException {
        super();
        this.sslEngine = sslEngine;
        this.sslOut = new OpenSSLOutputStream(this);
        this.sslIn = new OpenSSLInputStream(this);
        this.delegate = socket;
        this.autoclose = autoclose;
        sslEngine.setHost(host);
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
        sslEngine.setEnabledCipherSuites(suites);
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
        if (sslEngine.isHandshakeFinished() || sslEngine.isOutboundDone() || sslEngine.isInboundDone()) {
            return sslEngine.getSession();
        } else {
            try {
                startHandshake();
            } catch (IOException e) {
                logger.log(Level.WARNING, Messages.MESSAGES.handshakeFailed(), e);
            }
            return sslEngine.getSession();
        }
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
        if (delegate == null) {
            super.close();
        } else if (autoclose) {
            delegate.close();
        }
        sslEngine.shutdown();
    }

    private void runHandshake() throws IOException {
        if (handshakeDone) {
            return;
        }
        try (DefaultByteBufferPool.PooledByteBuffer directPooled = DefaultByteBufferPool.DIRECT_POOL.allocate()) {
            boolean underflow = false;
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
                        try (DefaultByteBufferPool.PooledByteBuffer indirectPooled = DefaultByteBufferPool.HEAP_POOL.allocate()) {
                            ByteBuffer ind = indirectPooled.getBuffer();
                            ind.put(buffer);
                            ind.flip();
                            getDelegateOutputStream().write(ind.array(), ind.arrayOffset() + ind.position(), ind.remaining());
                        }
                    }
                } else {
                    boolean freeIndirect = true;
                    DefaultByteBufferPool.PooledByteBuffer indirectPooled = DefaultByteBufferPool.HEAP_POOL.allocate();
                    try  {
                        int readOffset = 0;
                        int read = getDelegateInputStream().read(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset() + readOffset, indirectPooled.getBuffer().remaining());
                        readOffset += read;

                        if (read > 0) {
                            indirectPooled.getBuffer().position(readOffset);
                            indirectPooled.getBuffer().flip();
                        } else {
                            close();
                            throw new SSLException(MESSAGES.connectionClosed());
                        }
                        for (; ; ) {
                                if (unwrappedData != null) {
                                    throw new IllegalStateException(MESSAGES.runningHandshakeWithBufferedData());
                                }
                                unwrappedData = DefaultByteBufferPool.DIRECT_POOL.allocate();
                                buffer.clear();
                                buffer.put(indirectPooled.getBuffer());
                                buffer.flip();
                                result = sslEngine.unwrap(buffer, unwrappedData.getBuffer());
                                if(result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                    underflow = true;
                                }
                                indirectPooled.getBuffer().clear();
                                indirectPooled.getBuffer().put(buffer);
                                indirectPooled.getBuffer().flip();
                                if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                    //try and read some more from the socket
                                    indirectPooled.getBuffer().compact();
                                    readOffset = indirectPooled.getBuffer().position();
                                    continue;
                                }
                                if (unwrappedData.getBuffer().position() == 0) {
                                    unwrappedData.close();
                                    unwrappedData = null;
                                }
                                if(indirectPooled.getBuffer().hasRemaining()) {
                                    freeIndirect = false;
                                    dataToUnwrap = indirectPooled;
                                    if(underflow) {
                                        break;
                                    }
                                } else {
                                    break;
                                }

                        }
                    } catch (IOException | RuntimeException e) {
                        this.close();
                        throw e;
                    }
                    finally {
                        if(freeIndirect) {
                            indirectPooled.close();
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
        if (delegate == null) {
            return super.getInputStream();
        }
        return delegate.getInputStream();
    }

    public int read() throws IOException {
        final byte[] b = new byte[1];
        final int numRead = read(b);
        return numRead == -1 ? -1 : (b[0] & 0xFF);
    }

    public int read(byte[] b, int off, int len) throws IOException {
        if (unwrappedData != null) {
            ByteBuffer buf = unwrappedData.getBuffer();
            int read = buf.remaining();
            if (len < buf.remaining()) {
                read = len;
            }
            buf.get(b, off, read);
            if (!buf.hasRemaining()) {
                unwrappedData.close();
                unwrappedData = null;
            }
            return read;
        }
        runHandshake();

        boolean first = true;
        int readOffset = 0;
        DefaultByteBufferPool.PooledByteBuffer indirectPooled;
        if (dataToUnwrap != null) {
            indirectPooled = dataToUnwrap;
            dataToUnwrap = null;
        } else {
            indirectPooled = DefaultByteBufferPool.HEAP_POOL.allocate();
            indirectPooled.getBuffer().flip();
        }
        boolean freeIndirect = true;
        try (DefaultByteBufferPool.PooledByteBuffer direct = DefaultByteBufferPool.DIRECT_POOL.allocate()){
            unwrappedData = DefaultByteBufferPool.DIRECT_POOL.allocate();
            for (; ; ) {
                if(!first) {
                    int read = getDelegateInputStream().read(indirectPooled.getBuffer().array(), indirectPooled.getBuffer().arrayOffset() + readOffset, indirectPooled.getBuffer().remaining());

                    if (read == -1) {
                        sslEngine.shutdown();
                        return -1;
                    }
                    readOffset += read;
                    indirectPooled.getBuffer().position(readOffset);
                    indirectPooled.getBuffer().flip();
                }
                first = false;
                direct.getBuffer().clear();
                direct.getBuffer().put(indirectPooled.getBuffer());
                direct.getBuffer().flip();
                SSLEngineResult result = sslEngine.unwrap(direct.getBuffer(), unwrappedData.getBuffer());
                indirectPooled.getBuffer().clear();
                indirectPooled.getBuffer().put(direct.getBuffer());
                indirectPooled.getBuffer().flip();
                unwrappedData.getBuffer().flip();
                if (result.bytesProduced() == 0) {
                    //try and read some more from the socket
                    indirectPooled.getBuffer().compact();
                    readOffset = indirectPooled.getBuffer().position();
                    unwrappedData.getBuffer().clear();
                    continue;
                }
                int ret = Math.min(len, unwrappedData.getBuffer().remaining());
                unwrappedData.getBuffer().get(b, off, ret);
                if (indirectPooled.getBuffer().hasRemaining()) {
                    freeIndirect = false;
                    dataToUnwrap = indirectPooled;
                }
                if(!unwrappedData.getBuffer().hasRemaining()) {
                    unwrappedData.close();
                    unwrappedData = null;
                }

                return ret;
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
        try (DefaultByteBufferPool.PooledByteBuffer uncompressedPooled = DefaultByteBufferPool.WRITE_DIRECT_POOL.allocate()) {
                try (DefaultByteBufferPool.PooledByteBuffer encryptedPooled = DefaultByteBufferPool.HEAP_POOL.allocate()) {
                    ByteBuffer buf = uncompressedPooled.getBuffer();
                    int toWrite = len;
                    int written = 0;
                    while (toWrite > 0) {
                        buf.clear();
                        int thisBufferAmount = Math.min(toWrite, buf.remaining());
                        buf.put(b, off + written, thisBufferAmount);
                        toWrite -= thisBufferAmount;
                        written += thisBufferAmount;
                        buf.flip();
                        while (buf.hasRemaining()) {
                            encryptedPooled.getBuffer().clear();
                            SSLEngineResult result = sslEngine.wrap(buf, encryptedPooled.getBuffer());
                            encryptedPooled.getBuffer().flip();
                            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                                close();
                                throw new IOException(MESSAGES.bufferOverflow());//should never happen
                            } else if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                close();
                                throw new IOException(MESSAGES.bufferUnderflow());//should never happen
                            } else if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                                close();
                                throw new IOException(MESSAGES.streamIsClosed());
                            }
                            int produced = result.bytesProduced();
                            if (produced > 0) {
                                getDelegateOutputStream().write(encryptedPooled.getBuffer().array(), encryptedPooled.getBuffer().arrayOffset(), encryptedPooled.getBuffer().remaining());
                            }
                        }
                    }
                }
        }

    }

    private OutputStream getDelegateOutputStream() throws IOException {
        if (delegate == null) {
            return super.getOutputStream();
        }
        return delegate.getOutputStream();
    }

    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }


    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        if (delegate == null) {
            super.connect(endpoint);
        } else {
            delegate.connect(endpoint);
        }

        if (!(endpoint instanceof InetSocketAddress))
            throw new IllegalArgumentException(MESSAGES.unsupportedAddressType());
        final InetSocketAddress address = (InetSocketAddress) endpoint;
        sslEngine.setHost(address.getHostName());
        sslEngine.setPort(address.getPort());
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (delegate == null) {
            super.connect(endpoint, timeout);
        } else {
            delegate.connect(endpoint, timeout);
        }

        if (!(endpoint instanceof InetSocketAddress))
            throw new IllegalArgumentException(MESSAGES.unsupportedAddressType());
        final InetSocketAddress address = (InetSocketAddress) endpoint;
        sslEngine.setHost(address.getHostName());
        sslEngine.setPort(address.getPort());
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        if (delegate == null) {
            super.bind(bindpoint);
        } else {
            delegate.bind(bindpoint);
        }
    }

    @Override
    public InetAddress getInetAddress() {
        if (delegate == null) {
            return super.getInetAddress();
        } else {
            return delegate.getInetAddress();
        }
    }

    @Override
    public InetAddress getLocalAddress() {
        if (delegate == null) {
            return super.getLocalAddress();
        } else {
            return delegate.getLocalAddress();
        }
    }

    @Override
    public int getPort() {
        if (delegate == null) {
            return super.getPort();
        } else {
            return delegate.getPort();
        }
    }

    @Override
    public int getLocalPort() {
        if (delegate == null) {
            return super.getLocalPort();
        } else {
            return delegate.getLocalPort();
        }
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        if (delegate == null) {
            return super.getRemoteSocketAddress();
        } else {
            return delegate.getRemoteSocketAddress();
        }
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        if (delegate == null) {
            return super.getLocalSocketAddress();
        } else {
            return delegate.getLocalSocketAddress();
        }
    }

    @Override
    public SocketChannel getChannel() {
        if (delegate == null) {
            return super.getChannel();
        } else {
            return delegate.getChannel();
        }
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        if (delegate == null) {
            super.setTcpNoDelay(on);
        } else {
            delegate.setTcpNoDelay(on);
        }
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        if (delegate == null) {
            return super.getTcpNoDelay();
        } else {
            return delegate.getTcpNoDelay();
        }
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        if (delegate == null) {
            super.setSoLinger(on, linger);
        } else {
            delegate.setSoLinger(on, linger);
        }
    }

    @Override
    public int getSoLinger() throws SocketException {
        if (delegate == null) {
            return super.getSoLinger();
        } else {
            return delegate.getSoLinger();
        }
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        if (delegate == null) {
            super.sendUrgentData(data);
        } else {
            delegate.sendUrgentData(data);
        }
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        if (delegate == null) {
            super.setOOBInline(on);
        } else {
            delegate.setOOBInline(on);
        }
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        if (delegate == null) {
            return super.getOOBInline();
        } else {
            return delegate.getOOBInline();
        }
    }

    @Override
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        if (delegate == null) {
            super.setSoTimeout(timeout);
        } else {
            delegate.setSoTimeout(timeout);
        }
    }

    @Override
    public synchronized int getSoTimeout() throws SocketException {
        if (delegate == null) {
            return super.getSoTimeout();
        } else {
            return delegate.getSoTimeout();
        }
    }

    @Override
    public synchronized void setSendBufferSize(int size) throws SocketException {
        if (delegate == null) {
            super.setSendBufferSize(size);
        } else {
            delegate.setSendBufferSize(size);
        }
    }

    @Override
    public synchronized int getSendBufferSize() throws SocketException {
        if (delegate == null) {
            return super.getSendBufferSize();
        } else {
            return delegate.getSendBufferSize();
        }
    }

    @Override
    public synchronized void setReceiveBufferSize(int size) throws SocketException {
        if (delegate == null) {
            super.setReceiveBufferSize(size);
        } else {
            delegate.setReceiveBufferSize(size);
        }
    }

    @Override
    public synchronized int getReceiveBufferSize() throws SocketException {
        if (delegate == null) {
            return super.getReceiveBufferSize();
        } else {
            return delegate.getReceiveBufferSize();
        }
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        if (delegate == null) {
            super.setKeepAlive(on);
        } else {
            delegate.setKeepAlive(on);
        }
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        if (delegate == null) {
            return super.getKeepAlive();
        } else {
            return delegate.getKeepAlive();
        }
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        if (delegate == null) {
            super.setTrafficClass(tc);
        } else {
            delegate.setTrafficClass(tc);
        }
    }

    @Override
    public int getTrafficClass() throws SocketException {
        if (delegate == null) {
            return super.getTrafficClass();
        } else {
            return delegate.getTrafficClass();
        }
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        if (delegate == null) {
            super.setReuseAddress(on);
        } else {
            delegate.setReuseAddress(on);
        }
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        if (delegate == null) {
            return super.getReuseAddress();
        } else {
            return delegate.getReuseAddress();
        }
    }

    @Override
    public void shutdownInput() throws IOException {
        if (delegate == null) {
            super.shutdownInput();
        } else {
            delegate.shutdownInput();
        }
    }

    @Override
    public void shutdownOutput() throws IOException {
        if (delegate == null) {
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
        if (delegate == null) {
            return super.isConnected();
        } else {
            return delegate.isConnected();
        }
    }

    @Override
    public boolean isBound() {
        if (delegate == null) {
            return super.isBound();
        } else {
            return delegate.isBound();
        }
    }

    @Override
    public boolean isClosed() {
        if (delegate == null) {
            return super.isClosed();
        } else {
            return delegate.isClosed();
        }
    }

    @Override
    public boolean isInputShutdown() {
        if (delegate == null) {
            return super.isInputShutdown();
        } else {
            return delegate.isInputShutdown();
        }
    }

    @Override
    public boolean isOutputShutdown() {
        if (delegate == null) {
            return super.isOutputShutdown();
        } else {
            return delegate.isOutputShutdown();
        }
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        if (delegate == null) {
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

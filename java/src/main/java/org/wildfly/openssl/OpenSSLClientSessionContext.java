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

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

import org.wildfly.openssl.util.ConcurrentDirectDeque;

/**
 * {@link OpenSSLSessionContext} implementation which offers extra methods which
 * are only useful for the client-side.
 */
public final class OpenSSLClientSessionContext extends OpenSSLSessionContext {
    private final Map<ClientSessionKey, CacheEntry> cache;
    private final ConcurrentDirectDeque<CacheEntry> accessQueue;

    /**
     * The session timeout in seconds
     */
    private volatile int timeout;
    private final long context;
    private int maxCacheSize = 100;
    private String handshakeKeyHost;
    private int handshakeKeyPort;

    OpenSSLClientSessionContext(long context) {
        super(context);
        this.context = context;
        cache = new ConcurrentHashMap<>();
        accessQueue = ConcurrentDirectDeque.newInstance();
    }

    @Override
    synchronized void sessionCreatedCallback(long ssl, long session, byte[] sessionId) {
        storeClientSideSession(getHandshakeKey(), ssl, session, sessionId);
    }

    @Override
    public void setSessionTimeout(int seconds) {
        if (seconds < 0) {
            throw new IllegalArgumentException();
        }
        this.timeout = seconds;
    }

    @Override
    public int getSessionTimeout() {
        return timeout;
    }

    @Override
    public void setSessionCacheSize(int size) {
        this.maxCacheSize = size;
        purgeOld();
    }

    @Override
    void remove(byte[] session) {
        super.remove(session);
    }

    @Override
    public int getSessionCacheSize() {
        return maxCacheSize;
    }

    public void setSessionCacheEnabled(boolean enabled) {
        long mode = enabled ? SSL.SSL_SESS_CACHE_CLIENT : SSL.SSL_SESS_CACHE_OFF;
        SSL.getInstance().setSessionCacheMode(context, mode);
    }

    public boolean isSessionCacheEnabled() {
        return SSL.getInstance().getSessionCacheMode(context) == SSL.SSL_SESS_CACHE_CLIENT;
    }

    void setHandshakeKeyHost(String handshakeKeyHost) {
        this.handshakeKeyHost = handshakeKeyHost;
    }

    void setHandshakeKeyPort(int handshakeKeyPort) {
        this.handshakeKeyPort = handshakeKeyPort;
    }

    public ClientSessionKey getHandshakeKey() {
        if (handshakeKeyHost != null && handshakeKeyPort >= 0) {
            return new ClientSessionKey(handshakeKeyHost, handshakeKeyPort);
        }
        return null;
    }

    synchronized void storeClientSideSession(ClientSessionKey key, long ssl, long sessionPointer, byte[] sessionId) {
        if (sessionId != null) {
            if (key != null) {
                // set with the session pointer from the found session
                final ClientSessionInfo foundSessionPtr = getCacheValue(key);
                if (foundSessionPtr != null) {
                    if (getSession(foundSessionPtr.sessionId) != null) {
                        removeCacheEntry(key);
                    } else {
                        removeCacheEntry(key);
                    }
                }
                addCacheEntry(key, new ClientSessionInfo(sessionPointer, sessionId, System.currentTimeMillis()));
                clientSessionCreated(ssl, sessionPointer, sessionId);
            }
        }
    }

    void tryAttachClientSideSession(final long ssl, final String host, final int port) {
        if (host != null && port >= 0) {
            final ClientSessionKey key = new ClientSessionKey(host, port);
            // set with the session pointer from the found session
            final ClientSessionInfo foundSessionPtr = getCacheValue(key);
            if (foundSessionPtr != null) {
                final OpenSSlSession existingSession = getOpenSSlSession(foundSessionPtr.sessionId);
                if(existingSession == null) {
                    removeCacheEntry(key);
                } else {
                    synchronized (existingSession) {
                        if (existingSession.isValid()) {
                            SSL.getInstance().setSession(ssl, foundSessionPtr.session);
                        }
                    }
                }
            }
        }
    }

    private void purgeOld() {
        if (maxCacheSize > 0) {
            final int removeSize = (cache.size() - maxCacheSize);
            if (removeSize > 0) {
                // Remove each entry until there are either no more entries or the size matches
                for (int i = 0; i < removeSize; i++) {
                    final CacheEntry oldest = accessQueue.poll();
                    if (oldest != null) {
                        removeCacheEntry(oldest.key());
                    } else {
                        // No need to continue as there are no more entries
                        break;
                    }
                }
            }
        }
    }

    private void addCacheEntry(final ClientSessionKey key, final ClientSessionInfo newValue) {
        CacheEntry value = cache.get(key);
        if (value == null) {
            value = new CacheEntry(key, newValue);
            final CacheEntry result = cache.putIfAbsent(key, value);
            if (result != null) {
                value = result;
                value.setValue(newValue);
            }
            bumpAccess(value);
            if (maxCacheSize > 0 && cache.size() > maxCacheSize) {
                // Remove the oldest entry
                final CacheEntry oldest = accessQueue.poll();
                if (oldest != value) {
                    removeCacheEntry(oldest.key());
                }
            }
        }
    }

    private ClientSessionInfo getCacheValue(final ClientSessionKey key) {
        CacheEntry cacheEntry = cache.get(key);
        if (cacheEntry == null) {
            return null;
        }
        if (timeout > 0) {
            long expires = cacheEntry.getTime() + (timeout * 1000);
            if (System.currentTimeMillis() > expires) {
                removeCacheEntry(key);
                return null;
            }
        }

        if (cacheEntry.hit() % 5 == 0) {
            bumpAccess(cacheEntry);
        }

        return cacheEntry.getValue();
    }

    private ClientSessionInfo removeCacheEntry(final ClientSessionKey key) {
        CacheEntry remove = cache.remove(key);
        if (remove != null) {
            Object old = remove.clearToken();
            if (old != null) {
                accessQueue.removeToken(old);
            }
            final ClientSessionInfo result =  remove.getValue();
            if (result != null) {
                invalidateIfPresent(result.sessionId);
            }
            return result;
        } else {
            return null;
        }
    }

    private void bumpAccess(final CacheEntry cacheEntry) {
        final Object prevToken = cacheEntry.claimToken();
        if (prevToken != Boolean.FALSE) {
            if (prevToken != null) {
                accessQueue.removeToken(prevToken);
            }

            Object token = null;
            try {
                token = accessQueue.offerLastAndReturnToken(cacheEntry);
            } catch (Throwable t) {
                // In case of disaster (OOME), we need to release the claim, so leave it as null
            }

            if (!cacheEntry.setToken(token) && token != null) { // Always set if null
                accessQueue.removeToken(token);
            }
        }
    }

    private static class ClientSessionKey {
        private final String host;
        private final int port;

        private ClientSessionKey(final String host, final int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        public int hashCode() {
            int result = 17;
            result = 31 * result + (host == null ? 0 : host.hashCode());
            result = 31 * result + port;
            return result;
        }

        @Override
        public boolean equals(final Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof ClientSessionKey)) {
                return false;
            }
            final ClientSessionKey other = (ClientSessionKey) obj;
            return Objects.equals(host, other.host) && port == other.port;
        }
    }

    private static final class ClientSessionInfo {
        final long session;
        final byte[] sessionId;
        final long time;

        private ClientSessionInfo(long session, byte[] sessionId, final long time) {
            this.session = session;
            this.sessionId = sessionId;
            this.time = time;
        }
    }

    private static final class CacheEntry {

        private static final Object CLAIM_TOKEN = new Object();

        private static final AtomicIntegerFieldUpdater<CacheEntry> hitsUpdater = AtomicIntegerFieldUpdater.newUpdater(CacheEntry.class, "hits");

        private static final AtomicReferenceFieldUpdater<CacheEntry, Object> tokenUpdater = AtomicReferenceFieldUpdater.newUpdater(CacheEntry.class, Object.class, "accessToken");

        private final ClientSessionKey key;
        private volatile ClientSessionInfo value;
        private volatile int hits = 1;
        private volatile Object accessToken;

        private CacheEntry(ClientSessionKey key, ClientSessionInfo value) {
            this.key = key;
            this.value = value;
        }

        void setValue(final ClientSessionInfo value) {
            this.value = value;
        }

        ClientSessionInfo getValue() {
            return value;
        }

        int hit() {
            for (; ; ) {
                int i = hits;

                if (hitsUpdater.weakCompareAndSet(this, i, ++i)) {
                    return i;
                }

            }
        }

        ClientSessionKey key() {
            return key;
        }

        Object claimToken() {
            for (; ; ) {
                Object current = this.accessToken;
                if (current == CLAIM_TOKEN) {
                    return Boolean.FALSE;
                }

                if (tokenUpdater.compareAndSet(this, current, CLAIM_TOKEN)) {
                    return current;
                }
            }
        }

        boolean setToken(Object token) {
            return tokenUpdater.compareAndSet(this, CLAIM_TOKEN, token);
        }

        Object clearToken() {
            Object old = tokenUpdater.getAndSet(this, null);
            return old == CLAIM_TOKEN ? null : old;
        }

        long getTime() {
            return value.time;
        }
    }
}

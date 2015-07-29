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
package io.undertow.openssl;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenSSL specific {@link SSLSessionContext} implementation.
 */
abstract class OpenSSLSessionContext implements SSLSessionContext {

    private final Map<Key, OpenSSlSession> sessions = new ConcurrentHashMap<>();

    /**
     * sessions that are in the process of handshaking. When the session is complete it is moved to the
     * sessions map. The sessions make is managed by the session callbacks
     */
    private final Map<Long, OpenSSlSession> handshakeSessions = new ConcurrentHashMap<>();

    private final OpenSSLSessionStats stats;
    final long context;

    OpenSSLSessionContext(long context) {
        this.context = context;
        stats = new OpenSSLSessionStats(context);
    }

    @Override
    public SSLSession getSession(byte[] bytes) {
        return sessions.get(new Key(bytes));
    }

    synchronized SSLSession getHandshakeSession(OpenSSLEngine ssl, byte[] id) {
        OpenSSlSession ret = sessions.get(new Key(id));
        if(ret != null) {
            return ret;
        }
        ret = handshakeSessions.get(ssl.getSsl());
        if(ret != null) {
            return ret;
        }
        ret = new OpenSSlSession(true, this);
        handshakeSessions.put(ssl.getSsl(), ret);
        return ret;
    }

    void removeHandshakeSession(long ssl) {
        handshakeSessions.remove(ssl);
    }

    @Override
    public Enumeration<byte[]> getIds() {
        final Iterator<Key> keys = new HashSet<>(sessions.keySet()).iterator();
        return new Enumeration<byte[]>() {
            @Override
            public boolean hasMoreElements() {
                return keys.hasNext();
            }

            @Override
            public byte[] nextElement() {
                return keys.next().data;
            }
        };
    }

    /**
     * Sets the SSL session ticket keys of this context.
     */
    public void setTicketKeys(byte[] keys) {
        if (keys == null) {
            throw OpenSSLLogger.ROOT_LOGGER.nullTicketKeys();
        }
        SSL.setSessionTicketKeys(context, keys);
    }

    /**
     * Enable or disable caching of SSL sessions.
     */
    public abstract void setSessionCacheEnabled(boolean enabled);

    /**
     * Return {@code true} if caching of SSL sessions is enabled, {@code false} otherwise.
     */
    public abstract boolean isSessionCacheEnabled();

    /**
     * Returns the stats of this context.
     */
    public OpenSSLSessionStats stats() {
        return stats;
    }

    void remove(byte[] session) {
        this.sessions.remove(new Key(session));
    }

    synchronized void sessionCreatedCallback(long ssl, long session, byte[] sessionId) {
        OpenSSlSession existing = handshakeSessions.remove(ssl);
        if(existing != null) {
            existing.initialised(session, ssl, sessionId);
            sessions.put(new Key(sessionId), existing);
        } else {
            final OpenSSlSession openSSlSession = new OpenSSlSession(true, this);
            openSSlSession.initialised(session, ssl, sessionId);
            sessions.put(new Key(sessionId), openSSlSession);
        }
    }

    synchronized void sessionRemovedCallback(byte[] sessionId) {
        sessions.remove(new Key(sessionId));
    }

    private static class Key {
        private final  byte[] data;

        private Key(byte[] data) {
            this.data = data;
        }

        public byte[] getData() {
            return data;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            return Arrays.equals(data, key.data);

        }

        @Override
        public int hashCode() {
            return data != null ? Arrays.hashCode(data) : 0;
        }
    }
}

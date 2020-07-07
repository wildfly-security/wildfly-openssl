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

    protected final Map<Key, OpenSSlSession> sessions = new ConcurrentHashMap<>();

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

    OpenSSlSession getOpenSSlSession(final byte[] sessionId) {
        return sessions.get(new Key(sessionId));
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
            throw new IllegalArgumentException("null ticket keys");
        }
        SSL.getInstance().setSessionTicketKeys(context, keys);
    }

    /**
     * Returns the stats of this context.
     */
    public OpenSSLSessionStats stats() {
        return stats;
    }

    void remove(byte[] session) {
        this.sessions.remove(new Key(session));
    }

    /**
     * Removes a cached session, represented by the {@code sessionId} and
     * {@link SSLSession#invalidate() invalidates} it
     *
     * @param sessionId The session id
     */
    void invalidateIfPresent(final byte[] sessionId) {
        final OpenSSlSession session = this.sessions.remove(new Key(sessionId));
        if (session == null) {
            return;
        }
        session.invalidate();
    }

    synchronized void sessionCreatedCallback(long ssl, long session, byte[] sessionId) {
        // This method gets invoked every time a new session is established. Note that prior to
        // TLS 1.3, sessions are established as part of the handshake but from TLS 1.3 onward,
        // sessions are not established until after handshake has completed
        final OpenSSlSession openSSlSession = new OpenSSlSession(true, this);
        openSSlSession.initialised(session, ssl, sessionId);
        if (sessionId != null) {
            sessions.put(new Key(sessionId), openSSlSession);
        }
    }

    synchronized void sessionRemovedCallback(byte[] sessionId) {
        sessions.remove(new Key(sessionId));
    }

    public void mergeHandshakeSession(SSLSession handshakeSession, byte[] sessionId) {
        Key k = new Key(sessionId);
        OpenSSlSession session = sessions.get(k);
        if(session == null) {
            return;
        }
        for(String key : handshakeSession.getValueNames()) {
            session.putValue(key, handshakeSession.getValue(key));
        }
    }

    protected void clientSessionCreated(long ssl, long sessionPointer, byte[] sessionId) {
        if (sessionId != null) {
            Key key = new Key(sessionId);
            OpenSSlSession existing = this.sessions.get(key);
            if (existing != null) {
                return;
            }
            OpenSSlSession session = new OpenSSlSession(false, this);
            session.initialised(sessionPointer, ssl, sessionId);
            this.sessions.put(key, session);
        }
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

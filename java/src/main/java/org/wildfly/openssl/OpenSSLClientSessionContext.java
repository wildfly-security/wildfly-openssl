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

/**
 * {@link OpenSSLSessionContext} implementation which offers extra methods which
 * are only useful for the client-side.
 */
public final class OpenSSLClientSessionContext extends OpenSSLSessionContext {
    private final Map<ClientSessionKey, ClientSessionInfo> clientSessions = new ConcurrentHashMap<>();

    /**
     * The session timeout in seconds
     */
    private volatile int timeout;
    private final long context;
    private int maxCacheSize = 100;
    private volatile boolean enabled;

    OpenSSLClientSessionContext(long context) {
        super(context);
        this.context = context;
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
        runExpire();
    }

    private void runExpire() {
        //todo
    }

    @Override
    public int getSessionCacheSize() {
        return maxCacheSize;
    }

    void storeClientSideSession(final long ssl, final String host, final int port, byte[] sessionId) {

        if (host != null && port >= 0) {

            // TODO (jrp) find a way to get the real host and port
            final ClientSessionKey key = new ClientSessionKey(host, port);
            // set with the session pointer from the found session
            final ClientSessionInfo foundSessionPtr = clientSessions.remove(key);
            if (foundSessionPtr != null) {
                SSL.getInstance().invalidateSession(foundSessionPtr.session);
            }
            final long sessionPointer = SSL.getInstance().getSession(ssl);
            clientSessions.put(key, new ClientSessionInfo(sessionPointer, sessionId));
            clientSessionCreated(ssl, sessionPointer, sessionId);
        }
    }

    byte[] tryAttachClientSideSession(final long ssl, final String host, final int port) {
        if (host != null && port >= 0) {
            // TODO (jrp) find a way to get the real host and port
            final ClientSessionKey key = new ClientSessionKey(host, port);
            // set with the session pointer from the found session
            final ClientSessionInfo foundSessionPtr = clientSessions.get(key);
            if (foundSessionPtr != null) {
                SSL.getInstance().setSession(ssl, foundSessionPtr.session);
                return foundSessionPtr.sessionId;
            }
        }
        return null;
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

        private ClientSessionInfo(long session, byte[] sessionId) {
            this.session = session;
            this.sessionId = sessionId;
        }
    }
}

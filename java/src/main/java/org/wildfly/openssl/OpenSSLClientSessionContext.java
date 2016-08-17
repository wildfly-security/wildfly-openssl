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

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link OpenSSLSessionContext} implementation which offers extra methods which
 * are only useful for the client-side.
 */
public final class OpenSSLClientSessionContext extends OpenSSLSessionContext {
    private final Map<ClientSessionKey, Long> clientSessions = new ConcurrentHashMap<>();
    private final Map<SessionIdKey, ClientSessionKey> sessionIds = new ConcurrentHashMap<>();

    OpenSSLClientSessionContext(long context) {
        super(context);
    }

    @Override
    public void setSessionTimeout(int seconds) {
        if (seconds < 0) {
            throw new IllegalArgumentException();
        }
        SSL.getInstance().setSessionCacheTimeout(context, seconds);
    }

    @Override
    public int getSessionTimeout() {
        return (int) SSL.getInstance().getSessionCacheTimeout(context);
    }

    @Override
    public void setSessionCacheSize(int size) {
        //todo:
    }

    @Override
    public int getSessionCacheSize() {
        //todo
        return 0;
    }

    @Override
    public void setSessionCacheEnabled(boolean enabled) {
        //todo
    }

    @Override
    public boolean isSessionCacheEnabled() {
        return true;
    }

    @Override
    synchronized void sessionRemovedCallback(byte[] sessionId) {
        super.sessionRemovedCallback(sessionId);
        final ClientSessionKey key = sessionIds.remove(new SessionIdKey(sessionId));
        if (key != null) {
            clientSessions.remove(key);
        }
    }

    @Override
    byte[] initClientSideSession(final long ssl, final String host, final int port) {
        final byte[] sessionId;
        if (host != null && port >= 0) {
            // TODO (jrp) find a way to get the real host and port
            final ClientSessionKey key = new ClientSessionKey(host, port);
            // set with the session pointer from the found session
            final Long foundSessionPtr = clientSessions.get(key);
            if (foundSessionPtr != null) {
                SSL.getInstance().setSession(ssl, foundSessionPtr);
            } else {
                final long sessionPointer = SSL.getInstance().getSession(ssl);
                clientSessions.put(key, sessionPointer);
                // TODO (jrp) this only seems to be invoked from the OpenSSLSession.invalidate(), but the documentation
                // TODO (jrp) indicates it should be invoked for each invocation of SSL_get1_session
                //SSL.getInstance().invalidateSession(sessionPointer);
            }
            sessionId = super.initClientSideSession(ssl, host, port);
            sessionIds.putIfAbsent(new SessionIdKey(sessionId), key);
        } else {
            sessionId = super.initClientSideSession(ssl, host, port);
        }
        return sessionId;
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

    private static class SessionIdKey {
        private final byte[] sessionId;

        private SessionIdKey(final byte[] sessionId) {
            this.sessionId = Arrays.copyOf(sessionId, sessionId.length);
        }

        @Override
        public int hashCode() {
            return sessionId == null ? 0 : Arrays.hashCode(sessionId);
        }

        @Override
        public boolean equals(final Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof SessionIdKey)) {
                return false;
            }
            final SessionIdKey other = (SessionIdKey) obj;
            return Arrays.equals(sessionId, other.sessionId);
        }
    }
}

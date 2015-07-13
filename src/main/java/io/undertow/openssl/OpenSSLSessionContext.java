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
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenSSL specific {@link SSLSessionContext} implementation.
 */
public abstract class OpenSSLSessionContext implements SSLSessionContext {

    private final Map<byte[], OpenSSlSession> sessions = new ConcurrentHashMap<>();

    private final OpenSSLSessionStats stats;
    final long context;

    OpenSSLSessionContext(long context) {
        this.context = context;
        stats = new OpenSSLSessionStats(context);
    }

    @Override
    public SSLSession getSession(byte[] bytes) {
        return sessions.get(bytes);
    }

    @Override
    public Enumeration<byte[]> getIds() {
        final Iterator<byte[]> keys = new HashSet<>(sessions.keySet()).iterator();
        return new Enumeration<byte[]>() {
            @Override
            public boolean hasMoreElements() {
                return keys.hasNext();
            }

            @Override
            public byte[] nextElement() {
                return keys.next();
            }

            public Iterator<byte[]> asIterator() {
                return keys;
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
        this.sessions.remove(session);
    }

}

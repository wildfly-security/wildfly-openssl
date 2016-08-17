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

/**
 * Stats exposed by an OpenSSL session context.
 *
 * @see <a href="https://www.openssl.org/docs/ssl/SSL_CTX_sess_number.html"><code>SSL_CTX_sess_number</code></a>
 */
public final class OpenSSLSessionStats {

    private final long context;

    OpenSSLSessionStats(long context) {
        this.context = context;
    }

    /**
     * Returns the current number of sessions in the internal session cache.
     */
    public long number() {
        return SSL.getInstance().sessionNumber(context);
    }

    /**
     * Returns the number of started SSL/TLS handshakes in client mode.
     */
    public long connect() {
        return SSL.getInstance().sessionConnect(context);
    }

    /**
     * Returns the number of successfully established SSL/TLS sessions in client mode.
     */
    public long connectGood() {
        return SSL.getInstance().sessionConnectGood(context);
    }

    /**
     * Returns the number of start renegotiations in client mode.
     */
    public long connectRenegotiate() {
        return SSL.getInstance().sessionConnectRenegotiate(context);
    }

    /**
     * Returns the number of started SSL/TLS handshakes in server mode.
     */
    public long accept() {
        return SSL.getInstance().sessionAccept(context);
    }

    /**
     * Returns the number of successfully established SSL/TLS sessions in server mode.
     */
    public long acceptGood() {
        return SSL.getInstance().sessionAcceptGood(context);
    }

    /**
     * Returns the number of start renegotiations in server mode.
     */
    public long acceptRenegotiate() {
        return SSL.getInstance().sessionAcceptRenegotiate(context);
    }

    /**
     * Returns the number of successfully reused sessions. In client mode, a session set with {@code SSL_set_session}
     * successfully reused is counted as a hit. In server mode, a session successfully retrieved from internal or
     * external cache is counted as a hit.
     */
    public long hits() {
        return SSL.getInstance().sessionHits(context);
    }

    /**
     * Returns the number of successfully retrieved sessions from the external session cache in server mode.
     */
    public long cbHits() {
        return SSL.getInstance().sessionCbHits(context);
    }

    /**
     * Returns the number of sessions proposed by clients that were not found in the internal session cache
     * in server mode.
     */
    public long misses() {
        return SSL.getInstance().sessionMisses(context);
    }

    /**
     * Returns the number of sessions proposed by clients and either found in the internal or external session cache
     * in server mode, but that were invalid due to timeout. These sessions are not included in the {@link #hits()}
     * count.
     */
    public long timeouts() {
        return SSL.getInstance().sessionTimeouts(context);
    }

    /**
     * Returns the number of sessions that were removed because the maximum session cache size was exceeded.
     */
    public long cacheFull() {
        return SSL.getInstance().sessionCacheFull(context);
    }
}

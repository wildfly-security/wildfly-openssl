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

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Stuart Douglas
 */
class OpenSSlSession implements SSLSession {

    private final boolean server;
    private final OpenSSLSessionContext sessionContext;

    private static final Certificate[] EMPTY_CERTIFICATES = new Certificate[0];

    private volatile X509Certificate[] x509PeerCerts;

    private volatile Certificate[] peerCerts;

    // lazy init for memory reasons
    private Map<String, Object> values;

    private volatile long creationTime = System.currentTimeMillis();

    private volatile byte[] sessionId;
    private volatile long sessionPointer;
    private boolean valid = true;
    private String cipherSuite = OpenSSLEngine.INVALID_CIPHER;
    private String protocol = "TLS";

    OpenSSlSession(boolean server, OpenSSLSessionContext sessionContext) {
        this.server = server;
        this.sessionContext = sessionContext;
    }


    @Override
    public byte[] getId() {
        return sessionId;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return sessionContext;
    }

    @Override
    public long getCreationTime() {
        // We need ot multiple by 1000 as openssl uses seconds and we need milli-seconds.
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        // TODO: Add proper implementation
        return getCreationTime();
    }

    @Override
    public void invalidate() {
        if (valid) {
            SSL.invalidateSession(sessionPointer);
            valid = false;
        }
    }

    @Override
    public boolean isValid() {
        return valid;
    }

    @Override
    public synchronized void putValue(String name, Object value) {
        if (name == null) {
            throw new IllegalArgumentException("Name was null");
        }
        if (value == null) {
            throw new IllegalArgumentException("Value was null");
        }
        Map<String, Object> values = this.values;
        if (values == null) {
            // Use size of 2 to keep the memory overhead small
            values = this.values = new HashMap<>(2);
        }
        Object old = values.put(name, value);
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
        notifyUnbound(old, name);
    }

    @Override
    public synchronized Object getValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Name was null");
        }
        if (values == null) {
            return null;
        }
        return values.get(name);
    }

    @Override
    public synchronized void removeValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Name was null");
        }
        Map<String, Object> values = this.values;
        if (values == null) {
            return;
        }
        Object old = values.remove(name);
        notifyUnbound(old, name);
    }

    @Override
    public synchronized String[] getValueNames() {
        Map<String, Object> values = this.values;
        if (values == null || values.isEmpty()) {
            return new String[0];
        }
        return values.keySet().toArray(new String[values.size()]);
    }

    private void notifyUnbound(Object value, String name) {
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        if (peerCerts == null) {
            throw new SSLPeerUnverifiedException("Unverified Peer");
        }
        return peerCerts;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        // TODO: Find out how to get these
        return EMPTY_CERTIFICATES;
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        if (x509PeerCerts == null) {
            throw new SSLPeerUnverifiedException("Unverified Peer");
        }
        return x509PeerCerts;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        Certificate[] peer = getPeerCertificates();
        if (peer == null || peer.length == 0) {
            return null;
        }
        return principal(peer);
    }

    @Override
    public Principal getLocalPrincipal() {
        Certificate[] local = getLocalCertificates();
        if (local == null || local.length == 0) {
            return null;
        }
        return principal(local);
    }

    private Principal principal(Certificate[] certs) {
        return ((java.security.cert.X509Certificate) certs[0]).getIssuerX500Principal();
    }

    @Override
    public String getCipherSuite() {
        return cipherSuite;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }

    @Override
    public String getPeerHost() {
        return null;
    }

    @Override
    public int getPeerPort() {
        return 0;
    }

    @Override
    public int getPacketBufferSize() {
        return OpenSSLEngine.MAX_ENCRYPTED_PACKET_LENGTH;
    }

    @Override
    public int getApplicationBufferSize() {
        return OpenSSLEngine.MAX_PLAINTEXT_LENGTH;
    }


    private void initPeerCertChain(long ssl) {
        byte[][] chain = SSL.getPeerCertChain(ssl);
        byte[] clientCert;
        if (server) {
            // if used on the server side SSL_get_peer_cert_chain(...) will not include the remote peer certificate.
            // We use SSL_get_peer_certificate to get it in this case and add it to our array later.
            //
            // See https://www.openssl.org/docs/ssl/SSL_get_peer_cert_chain.html
            clientCert = SSL.getPeerCertificate(ssl);
        } else {
            clientCert = null;
        }

        if (chain == null && clientCert == null) {
            peerCerts = null;
            return;
        }
        int len = 0;
        if (chain != null) {
            len += chain.length;
        }

        int i = 0;
        Certificate[] peerCerts;
        if (clientCert != null) {
            len++;
            peerCerts = new Certificate[len];
            peerCerts[i++] = new OpenSslX509Certificate(clientCert);
        } else {
            peerCerts = new Certificate[len];
        }
        if (chain != null) {
            int a = 0;
            for (; i < peerCerts.length; i++) {
                peerCerts[i] = new OpenSslX509Certificate(chain[a++]);
            }
        }
        this.peerCerts = peerCerts;
    }

    public void initx509PeerCertChain(long ssl) {
        if (SSL.isInInit(ssl) != 0) {
            this.x509PeerCerts = null;
            return;
        }
        byte[][] chain = SSL.getPeerCertChain(ssl);
        if (chain == null) {
            this.x509PeerCerts = null;
            return;
        }
        X509Certificate[] peerCerts = new X509Certificate[chain.length];
        for (int i = 0; i < peerCerts.length; i++) {
            try {
                peerCerts[i] = X509Certificate.getInstance(chain[i]);
            } catch (CertificateException e) {
                throw new IllegalStateException(e);
            }
        }
        x509PeerCerts = peerCerts;
    }

    void initialised(long pointer, long ssl, byte[] sessionId) {
        this.creationTime = System.currentTimeMillis();
        this.sessionPointer = pointer;
        this.sessionId = sessionId;
        initPeerCertChain(ssl);
        initx509PeerCertChain(ssl);
        initCipherSuite(ssl);
        initProtcol(ssl);
    }

    private void initProtcol(long ssl) {
        //TODO: fix this
        String version = SSL.getVersion(ssl);
        protocol = "TLS:" + version;
    }

    private void initCipherSuite(long ssl) {
        String c = OpenSSLEngine.toJavaCipherSuite(SSL.getCipherForSSL(ssl), ssl);
        if (c != null) {
            cipherSuite = c;
        }
    }


}

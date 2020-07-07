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

import static org.wildfly.openssl.OpenSSLEngine.isOpenSSL10;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Stuart Douglas
 */
class OpenSSlSession implements SSLSession {

    public static final String NULL_CIPHER = "TLS_NULL_WITH_NULL_NULL";
    private final boolean server;
    private final OpenSSLSessionContext sessionContext;

    private static final Certificate[] EMPTY_CERTIFICATES = new Certificate[0];

    private volatile X509Certificate[] x509PeerCerts;

    private volatile Certificate[] peerCerts;

    // lazy init for memory reasons
    private Map<String, Object> values;

    private volatile long creationTime;

    private volatile byte[] sessionId;
    private volatile long sessionPointer;
    private volatile boolean valid = true;
    private String cipherSuite = OpenSSLEngine.INVALID_CIPHER;
    private String protocol = "TLS";
    private boolean reused;

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
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        // TODO: Add proper implementation
        return getCreationTime();
    }

    @Override
    public synchronized void invalidate() {
        if (valid) {
            if(sessionPointer > 0) {
                SSL.getInstance().invalidateSession(sessionPointer); // this decrements the ref count and frees the session
            }
            sessionContext.remove(sessionId);
            sessionPointer = 0;
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
            throw new IllegalArgumentException(Messages.MESSAGES.nameWasNull());
        }
        if (value == null) {
            throw new IllegalArgumentException(Messages.MESSAGES.valueWasNull());
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
            throw new IllegalArgumentException(Messages.MESSAGES.nameWasNull());
        }
        if (values == null) {
            return null;
        }
        return values.get(name);
    }

    @Override
    public synchronized void removeValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException(Messages.MESSAGES.nameWasNull());
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
            throw new SSLPeerUnverifiedException(Messages.MESSAGES.unverifiedPeer());
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
            throw new SSLPeerUnverifiedException(Messages.MESSAGES.unverifiedPeer());
        }
        return x509PeerCerts;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        Certificate[] peer = getPeerCertificates();
        if (peer == null || peer.length == 0) {
            return null;
        }
        return firstCertificate(peer).getSubjectX500Principal();
    }

    @Override
    public Principal getLocalPrincipal() {
        Certificate[] local = getLocalCertificates();
        if (local == null || local.length == 0) {
            return null;
        }
        return firstCertificate(local).getSubjectX500Principal();
    }

    private java.security.cert.X509Certificate firstCertificate(Certificate[] certs) {
        return ((java.security.cert.X509Certificate) certs[0]);
    }

    @Override
    public String getCipherSuite() {
        if(cipherSuite == null) {
            return NULL_CIPHER;
        }
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

    boolean isReused() {
        return reused;
    }

    private void initPeerCertChain(long ssl) {
        byte[][] chain = SSL.getInstance().getPeerCertChain(ssl);
        byte[] clientCert;
        if (server) {
            // if used on the server side SSL_get_peer_cert_chain(...) will not include the remote peer certificate.
            // We use SSL_get_peer_certificate to get it in this case and add it to our array later.
            //
            // See https://www.openssl.org/docs/ssl/SSL_get_peer_cert_chain.html
            clientCert = SSL.getInstance().getPeerCertificate(ssl);
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

        X509Certificate[] x509Certificates = new X509Certificate[peerCerts.length];
        for(int j = 0; j < x509Certificates.length; ++ j) {
            try {
                x509Certificates[j] = X509Certificate.getInstance(peerCerts[j].getEncoded());
            } catch (CertificateException|CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
        x509PeerCerts = x509Certificates;
    }

    void initialised(long pointer, long ssl, byte[] sessionId) {
        this.sessionPointer = pointer;
        this.sessionId = sessionId;
        initCreationTime(ssl);
        initPeerCertChain(ssl);
        initCipherSuite(ssl);
        initProtocol(ssl);
        initReused(ssl);
    }

    void initialised(long ssl) {
        initCreationTime(ssl);
        initSessionId(ssl);
        initPeerCertChain(ssl);
        initCipherSuite(ssl);
        initProtocol(ssl);
        initReused(ssl);
    }

    private void initSessionId(long ssl) {
        sessionId = SSL.getInstance().getSessionId(ssl);
    }

    private void initProtocol(long ssl) {
        protocol = SSL.getInstance().getVersion(ssl);
    }

    private void initCipherSuite(long ssl) {
        String c = OpenSSLEngine.toJavaCipherSuite(SSL.getInstance().getCipherForSSL(ssl), ssl);
        if (c != null) {
            cipherSuite = c;
        }
    }

    private void initCreationTime(long ssl) {
        // We need to multiply by 1000 as openssl uses seconds and we need milli-seconds.
        creationTime = SSL.getInstance().getTime(ssl) * 1000L;
    }

    private void initReused(long ssl) {
        if (isOpenSSL10()) {
            reused = false; // ssl_session_reused did not exist in OpenSSL 1.0.x
        } else {
            reused = SSL.getInstance().getSSLSessionReused(ssl);
        }
    }

}

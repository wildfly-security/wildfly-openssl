package io.undertow.openssl;

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

import static io.undertow.openssl.OpenSSLLogger.ROOT_LOGGER;

/**
 * @author Stuart Douglas
 */
class OpenSSlSession implements SSLSession {

    private static final Certificate[] EMPTY_CERTIFICATES = new Certificate[0];

    private OpenSSLEngine engine;
    // SSLSession implementation seems to not need to be thread-safe so no need for volatile etc.
    private X509Certificate[] x509PeerCerts;

    private volatile Certificate[] peerCerts;

    // lazy init for memory reasons
    private Map<String, Object> values;

    public OpenSSlSession(OpenSSLEngine engine) {
        this.engine = engine;
    }

    /**
     * Callen when resuming a session
     * @param engine The engine
     */
    void setOpenSSLEngine(OpenSSLEngine engine) {
        this.engine = engine;
    }

    @Override
    public byte[] getId() {
        // We don't cache that to keep memory usage to a minimum.
        byte[] id = SSL.getSessionId(engine.getSsl());
        if (id == null) {
            // The id should never be null, if it was null then the SESSION itself was not valid.
            throw ROOT_LOGGER.noSession();
        }
        return id;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return engine.getSessionContext();
    }

    @Override
    public long getCreationTime() {
        // We need ot multiple by 1000 as openssl uses seconds and we need milli-seconds.
        return SSL.getTime(engine.getSsl()) * 1000L;
    }

    @Override
    public long getLastAccessedTime() {
        // TODO: Add proper implementation
        return getCreationTime();
    }

    @Override
    public void invalidate() {
        SSL.invalidateSession(engine.getSsl());
        engine.clearSession();
    }

    @Override
    public boolean isValid() {
        return false;
    }

    @Override
    public void putValue(String name, Object value) {
        if (name == null) {
            throw ROOT_LOGGER.nullName();
        }
        if (value == null) {
            throw ROOT_LOGGER.nullValue();
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
    public Object getValue(String name) {
        if (name == null) {
            throw ROOT_LOGGER.nullName();
        }
        if (values == null) {
            return null;
        }
        return values.get(name);
    }

    @Override
    public void removeValue(String name) {
        if (name == null) {
            throw ROOT_LOGGER.nullName();
        }
        Map<String, Object> values = this.values;
        if (values == null) {
            return;
        }
        Object old = values.remove(name);
        notifyUnbound(old, name);
    }

    @Override
    public String[] getValueNames() {
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
        // these are lazy created to reduce memory overhead
        Certificate[] c = peerCerts;
        if (c == null) {
            if (SSL.isInInit(engine.getSsl()) != 0) {
                throw ROOT_LOGGER.unverifiedPeer();
            }
            c = peerCerts = initPeerCertChain();
        }
        return c;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        // TODO: Find out how to get these
        return EMPTY_CERTIFICATES;
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        //we need to get these eagerly, as they are not availble if a session is resumed
        X509Certificate[] c = x509PeerCerts;
        if (c == null) {
            if (SSL.isInInit(engine.getSsl()) != 0) {
                throw ROOT_LOGGER.unverifiedPeer();
            }
            byte[][] chain = SSL.getPeerCertChain(engine.getSsl());
            if (chain == null) {
                throw ROOT_LOGGER.unverifiedPeer();
            }
            X509Certificate[] peerCerts = new X509Certificate[chain.length];
            for (int i = 0; i < peerCerts.length; i++) {
                try {
                    peerCerts[i] = X509Certificate.getInstance(chain[i]);
                } catch (CertificateException e) {
                    throw new IllegalStateException(e);
                }
            }
            c = x509PeerCerts = peerCerts;
        }
        return c;
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
        if (!engine.isHandshakeFinished()) {
            return OpenSSLEngine.INVALID_CIPHER;
        }
        if (engine.getCipher() == null) {
            String c = engine.toJavaCipherSuite(SSL.getCipherForSSL(engine.getSsl()));
            if (c != null) {
                engine.setCipher(c);
            }
        }
        return engine.getCipher();
    }

    @Override
    public String getProtocol() {
        String applicationProtocol = engine.getApplicationProtocol();
        if (applicationProtocol == null) {
            applicationProtocol = engine.getFallbackApplicationProtocol();
            if (applicationProtocol != null) {
                engine.setApplicationProtocol(applicationProtocol.replace(':', '_'));
            } else {
                engine.setApplicationProtocol(applicationProtocol = "");
            }
        }
        String version = SSL.getVersion(engine.getSsl());
        if (applicationProtocol.isEmpty()) {
            return version;
        } else {
            return version + ':' + applicationProtocol;
        }
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


    private Certificate[] initPeerCertChain() throws SSLPeerUnverifiedException {
        byte[][] chain = SSL.getPeerCertChain(engine.getSsl());
        byte[] clientCert;
        if (!engine.isClientMode()) {
            // if used on the server side SSL_get_peer_cert_chain(...) will not include the remote peer certificate.
            // We use SSL_get_peer_certificate to get it in this case and add it to our array later.
            //
            // See https://www.openssl.org/docs/ssl/SSL_get_peer_cert_chain.html
            clientCert = SSL.getPeerCertificate(engine.getSsl());
        } else {
            clientCert = null;
        }

        if (chain == null && clientCert == null) {

            throw ROOT_LOGGER.unverifiedPeer();
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
        return peerCerts;
    }
}

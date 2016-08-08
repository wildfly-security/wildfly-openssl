package io.undertow.openssl;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author Stuart Douglas
 */
public class SSLTestUtils {

    private static KeyStore loadKeyStore(final String name) throws IOException {
        final InputStream stream = BasicOpenSSLEngineTest.class.getClassLoader().getResourceAsStream(name);
        try {
            KeyStore loadedKeystore = KeyStore.getInstance("JKS");
            loadedKeystore.load(stream, "password".toCharArray());

            return loadedKeystore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(String.format("Unable to load KeyStore %s", name), e);
        } finally {
            stream.close();
        }
    }

    static SSLContext createSSLContext(String provider) throws IOException {
        KeyManager[] keyManagers;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(loadKeyStore("server.keystore"), "password".toCharArray());
            keyManagers = keyManagerFactory.getKeyManagers();
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new RuntimeException("Unable to initialise KeyManager[]", e);
        }

        TrustManager[] trustManagers = null;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(loadKeyStore("server.truststore"));
            trustManagers = trustManagerFactory.getTrustManagers();
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException("Unable to initialise TrustManager[]", e);
        }

        try {
            final SSLContext context = SSLContext.getInstance(provider);
            context.init(keyManagers, trustManagers, new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new RuntimeException("Unable to create and initialise the SSLContext", e);
        }
    }

}

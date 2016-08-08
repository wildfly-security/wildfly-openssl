package io.undertow.openssl;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class SslProtocolsTest {

    @BeforeClass
    public static void setup() {
        System.setProperty("javax.net.ssl.keyStore", new File("src/test/resources/client.keystore").getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStore", new File("src/test/resources/client.truststore").getAbsolutePath());
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        OpenSSLProvider.register();
    }

    @Test
    public void testCipherSuiteConverter() throws IOException {

        final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
        for (String cipher : socket.getSupportedCipherSuites()) {
            if (cipher.contains("EMPTY")) {
                continue;
            }
            String openSslCipherSuite = CipherSuiteConverter.toOpenSsl(cipher);
            Assert.assertNotNull(cipher, openSslCipherSuite);
            Assert.assertEquals(cipher, CipherSuiteConverter.toJava(openSslCipherSuite, cipher.substring(0, 3)));
        }
    }

    @Test
    public void testAvailableProtocols() throws IOException, NoSuchAlgorithmException {
        final AtomicReference<byte[]> sessionID = new AtomicReference<>();
        final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.2");

        //we only test a subset of ciphers
        //TODO: figure out which ones we need to support, and what sort of cert we need for each
        String[] suites = new String[]{
                //"TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                //"TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                //"TLS_RSA_WITH_AES_256_CBC_SHA"
        };

        for (String suite : suites) {

            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(new ServerSocket(7676), sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledCipherSuites(new String[]{suite});
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setEnabledCipherSuites(new String[]{suite});
            socket.connect(new InetSocketAddress("localhost", 7676));
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals("hello world", new String(data, 0, read));
            //make sure the names match
            String cipherSuite = socket.getSession().getCipherSuite();
            SSLEngine sslEngine = engineRef.get();
            SSLSession session = sslEngine.getSession();
            Assert.assertEquals(session.getCipherSuite(), cipherSuite);
            Assert.assertEquals(session.getCipherSuite(), suite);
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            socket.getSession().invalidate();
            socket.close();
            echo.stop();
        }
    }
}

package io.undertow.openssl;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class BasicOpenSSLEngineTest {

    @Test
    public void basicOpenSSLTest() throws IOException, NoSuchAlgorithmException {
        try (ServerSocket serverSocket = new ServerSocket(7676)) {
            OpenSSLProvider.register();
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1");

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID));
            acceptThread.start();
            System.setProperty("javax.net.ssl.keyStore", new File("src/test/resources/client.keystore").getAbsolutePath());
            System.setProperty("javax.net.ssl.trustStore", new File("src/test/resources/client.truststore").getAbsolutePath());
            System.setProperty("javax.net.ssl.keyStorePassword", "password");
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.connect(new InetSocketAddress("localhost", 7676));
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals("hello world", new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
        }
    }
}

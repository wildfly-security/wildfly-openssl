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

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class BasicOpenSSLSocketTest {

    @Test
    public void basicOpenSSLTest() throws IOException, NoSuchAlgorithmException {
        System.setProperty("javax.net.ssl.keyStore", new File("src/test/resources/client.keystore").getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStore", new File("src/test/resources/client.truststore").getAbsolutePath());
        System.setProperty("javax.net.ssl.keyStorePassword", "password");

        try (ServerSocket serverSocket = new ServerSocket(7676)) {
            OpenSSLProvider.register();
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext("TLSv1"), sessionID));
            acceptThread.start();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1");
            final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
            socket.connect(new InetSocketAddress("localhost", 7676));
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals("hello world", new String(data, 0, read));
            //TODO: fix client session id
            //Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());

        }
    }

}

package io.undertow.openssl;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author Stuart Douglas
 */
public class Test {

    @org.junit.Test
    public void testSomeSuff() throws IOException {
        System.loadLibrary("utssl");

        final SSLHostConfig sslHostConfig = new SSLHostConfig();
        final SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.RSA);
        certificate.setCertificateFile("/Users/stuart/workspace/undertow-openssl/src/test/resources/server.crt");
        certificate.setCertificateKeyFile("/Users/stuart/workspace/undertow-openssl/src/test/resources/server.key");
        sslHostConfig.addCertificate(certificate);

        sslHostConfig.setCaCertificatePath("/Users/stuart/workspace/undertow-openssl/src/test/resources/ca.crt");
        sslHostConfig.setCaCertificateFile("/Users/stuart/workspace/undertow-openssl/src/test/resources/ca.crt");

        sslHostConfig.setConfigType(SSLHostConfig.Type.OPENSSL);
        sslHostConfig.setProtocols("TLSv1");
        sslHostConfig.setCiphers("ALL");
        sslHostConfig.setCertificateVerification("NONE");
        sslHostConfig.setHostName("localhost");
        sslHostConfig.setCertificateVerificationDepth(100);

        final OpenSSLContext sslContext = new OpenSSLContext(sslHostConfig, certificate);

        sslContext.init(null, null);

        Thread acceptThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    ServerSocket socket = new ServerSocket(7676);
                    while (true) {
                        final Socket s = socket.accept();
                        Thread t = new Thread(new Runnable() {
                            @Override
                            public void run() {
                                SSLEngine engine = sslContext.createSSLEngine();
                            }
                        });
                        t.start();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
        });
        acceptThread.start();

        final Socket socket = SSLSocketFactory.getDefault().createSocket();
        socket.connect(new InetSocketAddress("localhost", 7676));

    }
}

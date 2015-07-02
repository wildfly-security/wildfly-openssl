package io.undertow.openssl;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * @author Stuart Douglas
 */
public class Test {

    @org.junit.Test
    public void testSomeSuff() throws IOException {
        System.loadLibrary("utssl");

        ServerSocket socket = new ServerSocket(7676);
        final SSLHostConfig sslHostConfig = new SSLHostConfig();
        final SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.RSA);
        certificate.setCertificateFile("/Users/stuart/workspace/undertow/core/src/test/resources/server.crt");
        certificate.setCertificateKeyFile("/Users/stuart/workspace/undertow/core/src/test/resources/server.key");
        sslHostConfig.addCertificate(certificate);

        sslHostConfig.setCaCertificatePath("/Users/stuart/workspace/undertow/core/src/test/resources/ca.crt");
        sslHostConfig.setCaCertificateFile("/Users/stuart/workspace/undertow/core/src/test/resources/ca.crt");

        sslHostConfig.setConfigType(SSLHostConfig.Type.OPENSSL);
        sslHostConfig.setProtocols("TLSv1");
        sslHostConfig.setCiphers("ALL");
        sslHostConfig.setCertificateVerification("NONE");
        sslHostConfig.setHostName("localhost");
        sslHostConfig.setCertificateVerificationDepth(100);

        OpenSSLContext sslContext = new OpenSSLContext(sslHostConfig, certificate);

        sslContext.init(null, null);

    }
}

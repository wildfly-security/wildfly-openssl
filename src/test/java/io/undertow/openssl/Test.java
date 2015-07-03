package io.undertow.openssl;

import org.junit.Assert;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * @author Stuart Douglas
 */
public class Test {

    private static final ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);

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
                                byte[] bytes = new byte[20000];
                                ByteBuffer in = ByteBuffer.allocateDirect(20000);
                                ByteBuffer out = ByteBuffer.allocateDirect(20000);
                                ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
                                try {
                                    SSLEngineResult result = null;
                                    while (result == null || result.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.FINISHED) {
                                        in.clear();
                                        out.clear();
                                        if(result == null || result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                                            int read = s.getInputStream().read(bytes);
                                            in.put(bytes, 0, read);
                                            in.flip();
                                            result = engine.unwrap(in, out);
                                            if(result.bytesProduced() > 0) {
                                                System.out.println(out);
                                                out.flip();
                                                byte[] b = new byte[out.remaining()];
                                                out.get(b);
                                                dataStream.write(b);
                                            }
                                        } else if(result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                                            in.flip();
                                            result = engine.wrap(in, out);
                                            out.flip();
                                            int len = out.remaining();
                                            out.get(bytes, 0, len);
                                            s.getOutputStream().write(bytes, 0, len);
                                        }else if(result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                                            Runnable task = engine.getDelegatedTask();
                                            while (task != null) {
                                                task.run();
                                                task = engine.getDelegatedTask();
                                            }
                                        } else {
                                            throw new RuntimeException(result.toString());
                                        }
                                    }
                                    while (true) {
                                        in.clear();
                                        out.clear();
                                        if(dataStream.size() > 0) {
                                            String read = new String(dataStream.toByteArray());
                                            System.out.println(read);
                                            dataStream.reset();
                                            in.put((read + " world").getBytes(StandardCharsets.US_ASCII));
                                            in.flip();
                                            result = engine.wrap(in, out);
                                            out.flip();
                                            int len = out.remaining();
                                            out.get(bytes, 0, len);
                                            s.getOutputStream().write(bytes, 0, len);
                                        }
                                        int read = s.getInputStream().read(bytes);
                                        in.put(bytes, 0, read);
                                        in.flip();
                                        result = engine.unwrap(in, out);
                                        if(result.bytesProduced() > 0) {
                                            out.flip();
                                            byte[] b = new byte[out.remaining()];
                                            out.get(b);
                                            dataStream.write(b);
                                        }
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    throw new RuntimeException(e);
                                }

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
        System.setProperty("javax.net.ssl.keyStore", new File("src/test/resources/client.keystore").getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStore", new File("src/test/resources/client.truststore").getAbsolutePath());
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
        socket.connect(new InetSocketAddress("localhost", 7676));
        socket.getOutputStream().write("hello".getBytes(StandardCharsets.US_ASCII));
        byte[] data = new byte[100];
        int read = socket.getInputStream().read(data);
        Assert.assertEquals("hello world", new String(data, 0, read));

    }
}

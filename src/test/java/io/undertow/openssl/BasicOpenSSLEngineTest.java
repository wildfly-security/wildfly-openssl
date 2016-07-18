package io.undertow.openssl;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class BasicOpenSSLEngineTest {

    private static KeyStore loadKeyStore(final String name) throws IOException {
        final InputStream stream = BasicOpenSSLEngineTest.class.getClassLoader().getResourceAsStream(name);
        try {
            KeyStore loadedKeystore = KeyStore.getInstance("JKS");
            loadedKeystore.load(stream, "password".toCharArray());

            return loadedKeystore;
        } catch (KeyStoreException e) {
            throw new RuntimeException(String.format("Unable to load KeyStore %s", name), e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(String.format("Unable to load KeyStore %s", name), e);
        } catch (CertificateException e) {
            throw new RuntimeException(String.format("Unable to load KeyStore %s", name), e);
        } finally {
            stream.close();
        }
    }

    private static SSLContext createSSLContext() throws IOException {
        KeyManager[] keyManagers;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(loadKeyStore("server.keystore"), "password".toCharArray());
            keyManagers = keyManagerFactory.getKeyManagers();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to initialise KeyManager[]", e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException("Unable to initialise KeyManager[]", e);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to initialise KeyManager[]", e);
        }

        TrustManager[] trustManagers = null;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(loadKeyStore("server.truststore"));
            trustManagers = trustManagerFactory.getTrustManagers();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to initialise TrustManager[]", e);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to initialise TrustManager[]", e);
        }

        try {
            final SSLContext context = SSLContext.getInstance("openssl.TLSv1");
            context.init(keyManagers, trustManagers, new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new RuntimeException("Unable to create and initialise the SSLContext", e);
        }
    }


    @Test
    public void basicOpenSSLTest() throws IOException, NoSuchAlgorithmException {
        try (ServerSocket serverSocket = new ServerSocket(7676)) {
            OpenSSLProvider.register();
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = createSSLContext();

            Thread acceptThread = new Thread(() -> {
                try {
                    while (true) {
                        final Socket s = serverSocket.accept();
                        Thread t = new Thread(() -> {
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
                                    if (result == null || result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                                        int read = s.getInputStream().read(bytes);
                                        in.put(bytes, 0, read);
                                        in.flip();
                                        result = engine.unwrap(in, out);
                                        if (result.bytesProduced() > 0) {
                                            System.out.println(out);
                                            out.flip();
                                            byte[] b = new byte[out.remaining()];
                                            out.get(b);
                                            dataStream.write(b);
                                        }
                                    } else if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                                        in.flip();
                                        result = engine.wrap(in, out);
                                        out.flip();
                                        int len = out.remaining();
                                        out.get(bytes, 0, len);
                                        s.getOutputStream().write(bytes, 0, len);
                                    } else if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                                        Runnable task = engine.getDelegatedTask();
                                        while (task != null) {
                                            task.run();
                                            task = engine.getDelegatedTask();
                                        }
                                    } else {
                                        throw new RuntimeException(result.toString());
                                    }
                                }
                                sessionID.set(engine.getSession().getId());
                                while (true) {
                                    in.clear();
                                    out.clear();
                                    if (dataStream.size() > 0) {
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
                                    if(read == -1) {
                                        return;
                                    }
                                    in.put(bytes, 0, read);
                                    in.flip();
                                    result = engine.unwrap(in, out);
                                    if (result.bytesProduced() > 0) {
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

                        });
                        t.start();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
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
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
        }
    }
}

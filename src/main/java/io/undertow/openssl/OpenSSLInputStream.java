package io.undertow.openssl;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Stuart Douglas
 */
class OpenSSLInputStream extends InputStream {

    private final OpenSSLSocket socket;

    public OpenSSLInputStream(OpenSSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public int read() throws IOException {
        return socket.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return socket.read(b, off, len);
    }

    @Override
    public int read(byte[] b) throws IOException {
        return socket.read(b);
    }
}

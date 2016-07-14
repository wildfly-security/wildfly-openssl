package io.undertow.openssl;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Stuart Douglas
 */
public class OpenSSLOutputStream extends OutputStream {

    private final OpenSSLSocket socket;

    public OpenSSLOutputStream(OpenSSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public void write(int b) throws IOException {
        socket.write(b);
    }

    @Override
    public void flush() throws IOException {
        socket.flush();
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        socket.write(b, off, len);
    }

    @Override
    public void write(byte[] b) throws IOException {
        socket.write(b);
    }
}

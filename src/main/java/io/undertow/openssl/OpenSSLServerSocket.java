package io.undertow.openssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLServerSocket;

/**
 * @author Stuart Douglas
 */
public class OpenSSLServerSocket extends SSLServerSocket {

    private final OpenSSLContextSPI openSSLContextSPI;

    public OpenSSLServerSocket(OpenSSLContextSPI openSSLContextSPI) throws IOException {
        this.openSSLContextSPI = openSSLContextSPI;
    }

    public OpenSSLServerSocket(int port, OpenSSLContextSPI openSSLContextSPI) throws IOException {
        super(port);
        this.openSSLContextSPI = openSSLContextSPI;
    }

    public OpenSSLServerSocket(int port, int backlog, OpenSSLContextSPI openSSLContextSPI) throws IOException {
        super(port, backlog);
        this.openSSLContextSPI = openSSLContextSPI;
    }

    public OpenSSLServerSocket(int port, int backlog, InetAddress bindAddr, OpenSSLContextSPI openSSLContextSPI) throws IOException {
        super(port, backlog, bindAddr);
        this.openSSLContextSPI = openSSLContextSPI;
    }

    @Override
    public Socket accept() throws IOException {
        final Socket delegate = super.accept();
        return new OpenSSLSocket(delegate, true, openSSLContextSPI.createSSLEngine());
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return null;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return openSSLContextSPI.getAvailableCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {

    }

    @Override
    public void setNeedClientAuth(boolean need) {

    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {

    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setUseClientMode(boolean mode) {

    }

    @Override
    public boolean getUseClientMode() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {

    }

    @Override
    public boolean getEnableSessionCreation() {
        return false;
    }


}

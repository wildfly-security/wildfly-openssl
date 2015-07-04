package io.undertow.openssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;

/**
 * @author Stuart Douglas
 */
public class OpenSSLContext extends SSLContext {

    /**
     * Creates an SSLContext object.
     *
     */
    public OpenSSLContext(SSLHostConfig config) throws SSLException {
        super(new OpenSSLContextSPI(config), null, "TLS");
    }
}

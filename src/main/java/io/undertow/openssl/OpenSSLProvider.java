package io.undertow.openssl;

import java.security.Provider;
import java.security.Security;

/**
 * @author Stuart Douglas
 */
public final class OpenSSLProvider extends Provider {

    private static boolean registered = false;

    protected OpenSSLProvider() {
        super("openssl", 1.0, "OpenSSL provider");
        put("SSLContext.openssl.TLSv1", OpenSSLContextSPI.class.getName() + "$" + OpenSSLContextSPI.OpenSSLTLS_1_0_ContextSpi.class.getSimpleName());
        put("SSLContext.openssl.TLSv1.1", OpenSSLContextSPI.class.getName() + "$" + OpenSSLContextSPI.OpenSSLTLS_1_1_ContextSpi.class.getSimpleName());
        put("SSLContext.openssl.TLSv1.2", OpenSSLContextSPI.class.getName() + "$" + OpenSSLContextSPI.OpenSSLTLS_1_2_ContextSpi.class.getSimpleName());
    }

    public synchronized static void register() {
        if (!registered) {
            registered = true;
            Security.addProvider(new OpenSSLProvider());
        }
    }
}

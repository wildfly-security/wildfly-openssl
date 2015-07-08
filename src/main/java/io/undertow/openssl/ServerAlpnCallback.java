package io.undertow.openssl;

/**
 * @author Stuart Douglas
 */
interface ServerALPNCallback {

    java.lang.String select(String[] protocols);
}

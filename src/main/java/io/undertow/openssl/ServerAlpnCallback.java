package io.undertow.openssl;

/**
 * @author Stuart Douglas
 */
public interface ServerAlpnCallback {

    java.lang.String select(String[] protocols);
}

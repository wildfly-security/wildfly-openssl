package io.undertow.openssl;

/**
 * @author Stuart Douglas
 */
public class Test {

    public static void main(String[] args) {
        System.loadLibrary("utssl");
        SSL.print();
    }
}

package org.wildfly.openssl;

import javax.net.ssl.X509TrustManager;
import java.lang.ref.WeakReference;

public class OpenSSLCertVerifyCallback implements CertificateVerifier {

  private X509TrustManager x509TrustManager;
  private WeakReference<OpenSSLContextSPI> contextSPIReference;

  public OpenSSLCertVerifyCallback(final X509TrustManager x509TrustManager, final OpenSSLContextSPI openSSLContextSPI) {
    this.x509TrustManager = x509TrustManager;
    this.contextSPIReference = new WeakReference<>(openSSLContextSPI);
  }

  @Override
  public boolean verify(long ssl, byte[][] chain, int cipherNo, boolean server) {
    final OpenSSLContextSPI openSSLContextSPI = this.contextSPIReference.get();
    if (openSSLContextSPI == null) {
      return false;
    }

    return openSSLContextSPI.verifyCallback(this.x509TrustManager, ssl, chain, cipherNo, server);
  }
}

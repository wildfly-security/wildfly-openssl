package org.wildfly.openssl;

import java.lang.ref.WeakReference;

public class OpenSSLEngineServerALPNCallback implements ServerALPNCallback {
  private WeakReference<OpenSSLEngine> sslEngineReference;

  public OpenSSLEngineServerALPNCallback(final OpenSSLEngine sslEngine) {
    this.sslEngineReference = new WeakReference<>(sslEngine);
  }

  @Override
  public String select(String[] protocols) {
    final OpenSSLEngine sslEngine = this.sslEngineReference.get();
    if (sslEngine == null) {
      return null;
    }

    return sslEngine.alpnCallback(protocols);
  }
}

package org.wildfly.openssl;

import org.wildfly.openssl.util.SNIUtil;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class SniClientAuthProvider {
  final Map<SNIMatcher, OpenSSLEngine.ClientAuthMode> serverNameToClientAuthMap;

  public SniClientAuthProvider(Map<String, OpenSSLEngine.ClientAuthMode> serverNameToClientAuthMap) {
    Set<Map.Entry<String, OpenSSLEngine.ClientAuthMode>> keySet = serverNameToClientAuthMap.entrySet();
    this.serverNameToClientAuthMap = keySet.stream()
            .collect(Collectors.toMap(e -> SNIHostName.createSNIMatcher(e.getKey()), Map.Entry::getValue));
  }

  public int getClientAuth(String serverName) {
    if (serverName != null) {
      final SNIMatcher bestSniMatch = SNIUtil.getBestSniHostNameMatch(serverName, serverNameToClientAuthMap.keySet());
      OpenSSLEngine.ClientAuthMode mode = serverNameToClientAuthMap.get(bestSniMatch);

      if (mode != null) {
        switch (mode) {
          case NONE:
            return SSL.SSL_CVERIFY_NONE;
          case REQUIRE:
            return SSL.SSL_CVERIFY_REQUIRE;
          case OPTIONAL:
            return SSL.SSL_CVERIFY_OPTIONAL;
        }
      }
    }

    return SSL.SSL_CVERIFY_UNSET;
  }
}

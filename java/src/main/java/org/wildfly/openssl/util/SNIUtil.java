package org.wildfly.openssl.util;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class SNIUtil {

  private static final Logger LOG = Logger.getLogger(SNIUtil.class.getName());

  public static SNIMatcher getBestSniHostNameMatch(String sniHostName, Set<SNIMatcher> sniMatchers) {
    final String lowerSniHostname = sniHostName.toLowerCase(Locale.ENGLISH);
    final SNIHostName lowerSniHostnameForMatcher = new SNIHostName(lowerSniHostname.getBytes(StandardCharsets.UTF_8));

    String sniHostnameAsWildcard = null;
    SNIHostName sniHostnameAsWildcardForMatcher = null;

    final int idx = lowerSniHostname.indexOf('.');

    if (idx > 0) {
      sniHostnameAsWildcard = "*" + lowerSniHostname.substring(idx);
      sniHostnameAsWildcardForMatcher = new SNIHostName(sniHostnameAsWildcard.getBytes(StandardCharsets.UTF_8));
    }

    for (final SNIMatcher hostnameMatcher: sniMatchers) {
      // find a ssl ctx by hostname, return if its a perfect match
      if (hostnameMatcher.matches(lowerSniHostnameForMatcher)) {
        return hostnameMatcher;
      }

      // check if context might be good with as a wildcard cert, but
      // there might be another ctx with a better match, so don't
      // return it yet, let's wait until we checked all ctx avail
      if (sniHostnameAsWildcard != null && hostnameMatcher.matches(sniHostnameAsWildcardForMatcher)) {
        return hostnameMatcher;
      }
    }

    return null;
  }

  public static SNIMatcher getHostnamesSNIMatcherFromCertificate(final X509Certificate cert) {
    if (cert == null) {
      return SNIHostName.createSNIMatcher("");
    }

    final StringBuilder builder = new StringBuilder();

    // extract all the valid "hostnames" from the SANs
    try {
      final Collection<List<?>> sansList = cert.getSubjectAlternativeNames();

      if (sansList != null && !sansList.isEmpty()) {
        for (final List<?> san : sansList) {
          if ((Integer) san.get(0) == 2) { // DNS
            final Object sanData = san.get(1);

            if (sanData instanceof String) {
              builder.append(Pattern.quote((String) sanData));
              builder.append("|");
            }
          }
        }
      }
    } catch (final CertificateParsingException ex) {
      final String msg = String.format("Unable to parse SANS of own certificate [%s].", cert.getSubjectX500Principal().getName());
      LOG.log(Level.WARNING, msg, ex);
    }

    final int len = builder.length();

    if (len > 0 && builder.charAt(len - 1) == '|') {
      builder.deleteCharAt(len - 1);
    }

    return SNIHostName.createSNIMatcher(builder.toString());
  }

}

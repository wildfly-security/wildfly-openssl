/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.undertow.openssl;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Represents the TLS configuration for a virtual host.
 */
public class SSLHostConfig {

    protected static final String DEFAULT_SSL_HOST_NAME = "_default_";
    protected static final Set<String> SSL_PROTO_ALL = new HashSet<>();

    static {
        /* Default used if protocols is not configured, also
           used if protocols="All" */
        /* If protocols is configured to be empty, the effective
           value comes from
           org.apache.tomcat.util.net.jsse.JSSESocketFactory.defaultServerProtocols
           (JSSE) resp. org.apache.tomcat.jni.SSL.SSL_PROTOCOL_ALL (OpenSSL)*/
        SSL_PROTO_ALL.add(SSL.SSL_PROTO_SSLv2Hello);
        SSL_PROTO_ALL.add(SSL.SSL_PROTO_TLSv1);
        SSL_PROTO_ALL.add(SSL.SSL_PROTO_TLSv1_1);
        SSL_PROTO_ALL.add(SSL.SSL_PROTO_TLSv1_2);
    }

    private String hostName = DEFAULT_SSL_HOST_NAME;

    // OpenSSL can handle multiple certs in a single config so the reference to
    // the context is here at the virtual host level. JSSE can't so the
    // reference is held on the certificate.
    private Long openSslContext;

    // Configuration properties

    // Common
    private String certificateRevocationListFile;
    private CertificateVerification certificateVerification = CertificateVerification.NONE;
    private int certificateVerificationDepth = 10;
    private String ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!kRSA";
    private LinkedHashSet<Cipher> cipherList = null;
    private List<String> jsseCipherNames = null;
    private boolean honorCipherOrder = true;
    private Set<String> protocols = new HashSet<>();
    private int sessionCacheSize = 0;
    private int sessionTimeout = 86400;
    private String certificateRevocationListPath;
    private boolean disableCompression = true;
    private boolean disableSessionTickets = false;
    private boolean insecureRenegotiation = false;

    public SSLHostConfig() {
        // Set defaults that can't be (easily) set when defining the fields.
        setProtocols(SSL.SSL_PROTO_ALL);
        setCiphers("ALL");
    }


    public Object getOpenSslContext() {
        return openSslContext;
    }


    public void setOpenSslContext(Long openSslContext) {
        this.openSslContext = openSslContext;
    }

    // ------------------------------------------- Nested configuration elements

    public void setCertificateRevocationListFile(String certificateRevocationListFile) {
        this.certificateRevocationListFile = certificateRevocationListFile;
    }


    public String getCertificateRevocationListFile() {
        return certificateRevocationListFile;
    }


    public void setCertificateVerification(String certificateVerification) {
        this.certificateVerification = CertificateVerification.fromString(certificateVerification);
    }


    public CertificateVerification getCertificateVerification() {
        return certificateVerification;
    }


    public void setCertificateVerificationDepth(int certificateVerificationDepth) {
        this.certificateVerificationDepth = certificateVerificationDepth;
    }


    public int getCertificateVerificationDepth() {
        return certificateVerificationDepth;
    }


    public void setCiphers(String ciphersList) {
        // Ciphers is stored in OpenSSL format. Convert the provided value if
        // necessary.
        if (ciphersList != null && !ciphersList.contains(":")) {
            StringBuilder sb = new StringBuilder();
            // Not obviously in OpenSSL format. May be a single OpenSSL or JSSE
            // cipher name. May be a comma separated list of cipher names
            String ciphers[] = ciphersList.split(",");
            for (String cipher : ciphers) {
                String trimmed = cipher.trim();
                if (trimmed.length() > 0) {
                    String openSSLName = OpenSSLCipherConfigurationParser.jsseToOpenSSL(trimmed);
                    if (openSSLName == null) {
                        // Not a JSSE name. Maybe an OpenSSL name or alias
                        openSSLName = trimmed;
                    }
                    if (sb.length() > 0) {
                        sb.append(':');
                    }
                    sb.append(openSSLName);
                }
            }
            this.ciphers = sb.toString();
        } else {
            this.ciphers = ciphersList;
        }
        this.cipherList = null;
        this.jsseCipherNames = null;

    }


    public String getCiphers() {
        return ciphers;
    }


    public LinkedHashSet<Cipher> getCipherList() {
        if (cipherList == null) {
            cipherList = OpenSSLCipherConfigurationParser.parse(ciphers);
        }
        return cipherList;
    }


    public List<String> getJsseCipherNames() {
        if (jsseCipherNames == null) {
            jsseCipherNames = OpenSSLCipherConfigurationParser.convertForJSSE(getCipherList());
        }
        return jsseCipherNames;
    }


    public void setHonorCipherOrder(boolean honorCipherOrder) {
        this.honorCipherOrder = honorCipherOrder;
    }


    public boolean getHonorCipherOrder() {
        return honorCipherOrder;
    }


    public void setHostName(String hostName) {
        this.hostName = hostName;
    }


    public String getHostName() {
        return hostName;
    }


    public void setProtocols(String input) {
        protocols.clear();

        // List of protocol names, separated by ",", "+" or "-".
        // Semantics is adding ("+") or removing ("-") from left
        // to right, starting with an empty protocol set.
        // Tokens are individual protocol names or "all" for a
        // default set of supported protocols.
        // Separator "," is only kept for compatibility and has the
        // same semantics as "+", except that it warns about a potentially
        // missing "+" or "-".

        // Split using a positive lookahead to keep the separator in
        // the capture so we can check which case it is.
        for (String value: input.split("(?=[-+,])")) {
            String trimmed = value.trim();
            // Ignore token which only consists of prefix character
            if (trimmed.length() > 1) {
                if (trimmed.charAt(0) == '+') {
                    trimmed = trimmed.substring(1).trim();
                    if (trimmed.equalsIgnoreCase(SSL.SSL_PROTO_ALL)) {
                        protocols.addAll(SSL_PROTO_ALL);
                    } else {
                        protocols.add(trimmed);
                    }
                } else if (trimmed.charAt(0) == '-') {
                    trimmed = trimmed.substring(1).trim();
                    if (trimmed.equalsIgnoreCase(SSL.SSL_PROTO_ALL)) {
                        protocols.removeAll(SSL_PROTO_ALL);
                    } else {
                        protocols.remove(trimmed);
                    }
                } else {
                    if (trimmed.charAt(0) == ',') {
                        trimmed = trimmed.substring(1).trim();
                    }
                    if (!protocols.isEmpty()) {
                        OpenSSLLogger.ROOT_LOGGER.prefixMissing(trimmed, getHostName());
                    }
                    if (trimmed.equalsIgnoreCase(SSL.SSL_PROTO_ALL)) {
                        protocols.addAll(SSL_PROTO_ALL);
                    } else {
                        protocols.add(trimmed);
                    }
                }
            }
        }
    }


    public Set<String> getProtocols() {
        return protocols;
    }

    public void setSessionCacheSize(int sessionCacheSize) {
        this.sessionCacheSize = sessionCacheSize;
    }


    public int getSessionCacheSize() {
        return sessionCacheSize;
    }


    public void setSessionTimeout(int sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }


    public int getSessionTimeout() {
        return sessionTimeout;
    }

    public void setCertificateRevocationListPath(String certificateRevocationListPath) {
        this.certificateRevocationListPath = certificateRevocationListPath;
    }


    public String getCertificateRevocationListPath() {
        return certificateRevocationListPath;
    }

    public void setDisableCompression(boolean disableCompression) {
        this.disableCompression = disableCompression;
    }


    public boolean getDisableCompression() {
        return disableCompression;
    }


    public void setDisableSessionTickets(boolean disableSessionTickets) {
        this.disableSessionTickets = disableSessionTickets;
    }


    public boolean getDisableSessionTickets() {
        return disableSessionTickets;
    }


    public void setInsecureRenegotiation(boolean insecureRenegotiation) {
        this.insecureRenegotiation = insecureRenegotiation;
    }


    public boolean getInsecureRenegotiation() {
        return insecureRenegotiation;
    }


    public enum CertificateVerification {
        NONE,
        OPTIONAL_NO_CA,
        OPTIONAL,
        REQUIRED;

        public static CertificateVerification fromString(String value) {
            if ("true".equalsIgnoreCase(value) ||
                    "yes".equalsIgnoreCase(value) ||
                    "require".equalsIgnoreCase(value) ||
                    "required".equalsIgnoreCase(value)) {
                return REQUIRED;
            } else if ("optional".equalsIgnoreCase(value) ||
                    "want".equalsIgnoreCase(value)) {
                return OPTIONAL;
            } else if ("optionalNoCA".equalsIgnoreCase(value) ||
                    "optional_no_ca".equalsIgnoreCase(value)) {
                return OPTIONAL_NO_CA;
            } else if ("false".equalsIgnoreCase(value) ||
                    "no".equalsIgnoreCase(value) ||
                    "none".equalsIgnoreCase(value)) {
                return NONE;
            } else {
                // Could be a typo. Don't default to NONE since that is not
                // secure. Force user to fix config. Could default to REQUIRED
                // instead.
                throw OpenSSLLogger.ROOT_LOGGER.invalidOption(value);
            }
        }
    }
}

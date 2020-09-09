/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.openssl;

import java.text.DecimalFormat;
import java.util.Formatter;
import java.util.ResourceBundle;

/**
 * @author Stuart Douglas
 */
public class Messages {

    private static final String CODE = "WFOPENSSL";

    public static Messages MESSAGES = new Messages();

    private static final String MSG1 = formatCode(1);
    private static final String MSG2 = formatCode(2);
    private static final String MSG3 = formatCode(3);
    private static final String MSG4 = formatCode(4);
    private static final String MSG5 = formatCode(5);
    private static final String MSG6 = formatCode(6);
    private static final String MSG7 = formatCode(7);
    private static final String MSG8 = formatCode(8);
    private static final String MSG9 = formatCode(9);
    private static final String MSG10 = formatCode(10);
    private static final String MSG11 = formatCode(11);
    private static final String MSG12 = formatCode(12);
    private static final String MSG13 = formatCode(13);
    private static final String MSG14 = formatCode(14);
    private static final String MSG15 = formatCode(15);
    private static final String MSG16 = formatCode(16);
    private static final String MSG17 = formatCode(17);
    private static final String MSG18 = formatCode(18);
    private static final String MSG19 = formatCode(19);
    private static final String MSG20 = formatCode(20);
    private static final String MSG21 = formatCode(21);
    private static final String MSG22 = formatCode(22);
    private static final String MSG23 = formatCode(23);
    private static final String MSG24 = formatCode(24);
    private static final String MSG25 = formatCode(25);
    private static final String MSG26 = formatCode(26);
    private static final String MSG27 = formatCode(27);
    private static final String MSG28 = formatCode(28);
    private static final String MSG29 = formatCode(29);
    private static final String MSG30 = formatCode(30);
    private static final String MSG31 = formatCode(31);
    private static final String MSG32 = formatCode(32);
    private static final String MSG33 = formatCode(33);
    private static final String MSG34 = formatCode(34);
    private static final String MSG35 = formatCode(35);
    private static final String MSG36 = formatCode(36);
    private static final String MSG37 = formatCode(37);
    private static final String MSG38 = formatCode(38);
    private static final String MSG39 = formatCode(39);
    private static final String MSG40 = formatCode(40);
    private static final String MSG41 = formatCode(41);
    private static final String MSG42 = formatCode(42);
    private static final String MSG43 = formatCode(43);

    private static String formatCode(int i) {
        return CODE + new DecimalFormat("0000").format(i);
    }

    private ResourceBundle properties;

    private Messages() {
        properties = ResourceBundle.getBundle("org.wildfly.openssl.OpenSSLMessages");
    }

    private String interpolate(String messageid, Object ... arguments) {
        StringBuilder sb = new StringBuilder(messageid);
        sb.append(' ');
        new Formatter(sb).format(properties.getString(messageid), (Object[]) arguments);
        return sb.toString();
    }

    public String couldNotFindLibSSL(String systemProperty, String attempted) {
        return interpolate(MSG1, systemProperty, attempted);
    }

    public String openSSLVersion(String version) {
        return interpolate(MSG2, version);
    }

    public String couldNotFindLibCrypto(String systemProperty, String attempted) {
        return interpolate(MSG3, systemProperty, attempted);
    }

    public String noSslContext() {
        return interpolate(MSG4);
    }

    public String sslWriteFailed(int sslWrote) {
        return interpolate(MSG5, sslWrote);
    }

    public String bufferIsNull() {
        return interpolate(MSG6);
    }

    public String invalidOffset(int offset, int length, int arrayLength) {
        return interpolate(MSG7, offset, length, arrayLength);
    }

    public String readFromSSLFailed(long error, int lastPrimingReadResult, String err) {
        return interpolate(MSG8, error, lastPrimingReadResult, err);
    }

    public String inboundIsClosed() {
        return interpolate(MSG9);
    }

    public String nullCipherSuites() {
        return interpolate(MSG10);
    }

    public String emptyCipherSuiteList() {
        return interpolate(MSG11);
    }

    public String failedCipherSuite(String cipherSuiteSpec) {
        return interpolate(MSG12, cipherSuiteSpec);
    }

    public String unsupportedProtocol(String p) {
        return interpolate(MSG13, p);
    }

    public String failedToInitializeCiphers() {
        return interpolate(MSG14);
    }

    public String failedToMakeSslContext() {
        return interpolate(MSG15);
    }

    public String failedToInitializeSslContext() {
        return interpolate(MSG16);
    }

    public String ignoringSecondInit() {
        return interpolate(MSG17);
    }

    public String couldNotFileSuitableKeyManager() {
        return interpolate(MSG18);
    }
    public String keyManagerDoesNotContainValidCertificates() {
        return interpolate(MSG19);
    }
    public String keyManagerIsMissing() {
        return interpolate(MSG20);
    }
    public String trustManagerIsMissing() {
        return interpolate(MSG21);
    }
    public String engineIsClosed() {
        return interpolate(MSG22);
    }

    public String renegotiationNotSupported() {
        return interpolate(MSG23);
    }
    public String oversidedPacket() {
        return interpolate(MSG24);
    }
    public String bufferAlreadyFreed() {
        return interpolate(MSG25);
    }
    public String bufferLeakDetected() {
        return interpolate(MSG26);
    }
    public String nameWasNull() {
        return interpolate(MSG27);
    }
    public String valueWasNull() {
        return interpolate(MSG28);
    }
    public String unverifiedPeer() {
        return interpolate(MSG29);
    }
    public String runningHandshakeWithBufferedData() {
        return interpolate(MSG30);
    }
    public String connectionClosed() {
        return interpolate(MSG31);
    }
    public String bufferOverflow() {
        return interpolate(MSG32);
    }
    public String bufferUnderflow() {
        return interpolate(MSG33);
    }
    public String unsupportedAddressType() {
        return interpolate(MSG34);
    }
    public String streamIsClosed() {
        return interpolate(MSG35);
    }
    public String unableToObtainPrivateKey() {
        return interpolate(MSG36);
    }
    public String directBufferDeallocatorInitializationFailed () {
        return interpolate(MSG37);
    }
    public String directBufferDeallocationFailed() {
        return interpolate(MSG38);
    }
    public String unsupportedProtocolVersion(int p) {
        return interpolate(MSG39, p);
    }
    public String handshakeFailed() {
        return interpolate(MSG41);
    }
    public String settingCipherSuites(String s) {
        return interpolate(MSG42, s);
    }
    public String settingTls13CipherSuites(String s) {
        return interpolate(MSG43, s);
    }
}

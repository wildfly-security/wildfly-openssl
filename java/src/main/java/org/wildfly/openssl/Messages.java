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
}

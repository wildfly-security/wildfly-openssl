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

    public static Messages INSTANCE = new Messages();

    private static final String MSG1 = formatCode(1);
    private static final String MSG2 = formatCode(2);
    private static final String MSG3 = formatCode(3);

    private static String formatCode(int i) {
        return CODE + new DecimalFormat("0000").format(i);
    }

    private ResourceBundle properties;

    private Messages() {
        properties = ResourceBundle.getBundle("org.wildfly.openssl.OpenSSLMessages");
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


    private String interpolate(String messageid, String ... arguments) {
        StringBuilder sb = new StringBuilder(messageid);
        sb.append(' ');
        new Formatter(sb).format(properties.getString(messageid), (Object[]) arguments);
        return sb.toString();
    }
}

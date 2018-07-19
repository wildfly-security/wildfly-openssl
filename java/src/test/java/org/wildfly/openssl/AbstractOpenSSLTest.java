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

import org.junit.BeforeClass;

/**
 * @author Stuart Douglas
 */
public class AbstractOpenSSLTest {

    private static boolean first = true;

    @BeforeClass
    public static void setup() {
        if(first) {
            first = false;
            OpenSSLProvider.register();
            if(System.getProperty("javax.net.ssl.keyStore") == null) {
                //for running the the IDE
                System.setProperty("javax.net.ssl.keyStore", "java/src/test/resources/client.keystore");
                System.setProperty("javax.net.ssl.trustStore", "java/src/test/resources/client.truststore");
                System.setProperty("javax.net.ssl.keyStorePassword", "password");
            }
            final String openSSLVersion = SSL.getInstance().version();
            // very crude (but acceptable) way to check the version
            if (openSSLVersion.contains("1.0.2")) {
                // 1.0.2 doesn't support "Extended master secret" extension, which is enabled in
                // Java by default. here we disable that extension on the Java side to allow
                // session resumption tests to pass
                // @see http://www.oracle.com/technetwork/java/javase/8u161-relnotes-4021379.html#JDK-8148421
                System.setProperty("jdk.tls.useExtendedMasterSecret", "false");
            }
        }
    }

}

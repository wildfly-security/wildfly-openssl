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

import java.security.Provider;
import java.security.Security;

/**
 * @author Stuart Douglas
 */
public final class OpenSSLProvider extends Provider {

    private static boolean registered = false;

    public static final OpenSSLProvider INSTANCE = new OpenSSLProvider();

    public OpenSSLProvider() {
        super("openssl", 1.0, "OpenSSL provider");
        put("SSLContext.openssl.TLS", OpenSSLContextSPI.OpenSSLTLSContextSpi.class.getName());
        put("SSLContext.openssl.TLSv1", OpenSSLContextSPI.OpenSSLTLS_1_0_ContextSpi.class.getName());
        put("SSLContext.openssl.TLSv1.1", OpenSSLContextSPI.OpenSSLTLS_1_1_ContextSpi.class.getName());
        put("SSLContext.openssl.TLSv1.2", OpenSSLContextSPI.OpenSSLTLS_1_2_ContextSpi.class.getName());
        put("SSLContext.openssl.DEFAULT", get("SSLContext.openssl.TLSv1.2"));
        put("SSLContext.TLS", get("SSLContext.openssl.TLS"));
        put("SSLContext.TLSv1", get("SSLContext.openssl.TLSv1"));
        put("SSLContext.TLSv1.1", get("SSLContext.openssl.TLSv1.1"));
        put("SSLContext.TLSv1.2", get("SSLContext.openssl.TLSv1.2"));
        put("SSLContext.DEFAULT", get("SSLContext.TLSv1.2"));
    }

    public static synchronized void register() {
        if (!registered) {
            registered = true;
            Security.addProvider(INSTANCE);
        }
    }
    public static synchronized void registerFirst() {
        if (!registered) {
            registered = true;
            Security.insertProviderAt(INSTANCE, 1);
        }
    }
}

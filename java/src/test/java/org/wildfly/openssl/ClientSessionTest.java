/*
 * JBoss, Home of Professional Open Source.
 *
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.openssl;

import static org.wildfly.openssl.OpenSSLEngine.isTLS13Supported;

import org.junit.Assume;
import org.junit.Test;

/**
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
public class ClientSessionTest extends ClientSessionTestBase {

    @Test
    public void testOpenSsl() throws Exception {
        testSessionId(SSLTestUtils.createSSLContext("openssl.TLSv1.2"), "openssl.TLSv1.2");
    }

    @Test
    public void testSessionTimeoutOpenSsl() throws Exception {
        testSessionTimeout("openssl.TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    public void testSessionTimeoutOpenSslTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testSessionTimeoutTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testSessionInvalidationOpenSsl() throws Exception {
        testSessionInvalidation("openssl.TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    public void testSessionInvalidationOpenSslTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testSessionInvalidationTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testSessionSizeOpenSsl() throws Exception {
        testSessionSize("openssl.TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    public void testSessionSizeOpenSslTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testSessionSizeTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testClientSessionInvalidationMultiThreadAccessOpenSsl() throws Exception {
        testClientSessionInvalidationMultiThreadAccess("openssl.TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    public void testClientSessionInvalidationMultiThreadAccessOpenSslTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testClientSessionInvalidationMultiThreadAccess("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

}

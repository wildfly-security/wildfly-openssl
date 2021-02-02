/*
 * JBoss, Home of Professional Open Source.
 *
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ClientSessionInteropTest extends ClientSessionTestBase {

    @Test
    public void testJsse() throws Exception {
        testSessionId(SSLTestUtils.createSSLContext("TLSv1.2"), "openssl.TLSv1.2");
    }

    @Test
    public void testSessionTimeoutJsse() throws Exception {
        testSessionTimeout("TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    public void testSessionTimeoutJsseTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testSessionTimeoutTLS13("TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testSessionInvalidationJsse() throws Exception {
        testSessionInvalidation("TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    public void testSessionInvalidationJsseTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testSessionInvalidationTLS13("TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testSessionSizeJsse() throws Exception {
        testSessionSize("TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    public void testSessionSizeJsseTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testSessionSizeTLS13("TLSv1.3", "openssl.TLSv1.3");
    }

    /**
     * Tests that invalidation of a client session, for whatever reason, when multiple threads
     * are involved in interacting with the server through a SSL socket, doesn't lead to a JVM crash
     *
     * @throws Exception
     */
    @Test
    public void testClientSessionInvalidationMultiThreadAccessJsse() throws Exception {
        testClientSessionInvalidationMultiThreadAccess("TLSv1.2", "openssl." + "TLSv1.2");
    }

    @Test
    public void testClientSessionInvalidationMultiThreadAccessJsseTLS13() throws Exception {
        Assume.assumeTrue(isTLS13Supported());
        testClientSessionInvalidationMultiThreadAccess("TLSv1.3" , "openssl.TLSv1.3");
    }

}

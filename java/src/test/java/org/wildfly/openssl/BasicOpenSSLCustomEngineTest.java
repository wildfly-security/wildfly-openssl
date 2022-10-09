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

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author Heyuan Liu
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BasicOpenSSLCustomEngineTest {

    @Test
    public void firstTestUnknownEngine() {
        String engine = System.setProperty(SSL.ORG_WILDFLY_OPENSSL_ENGINE, "unknown");
        try {
            AbstractOpenSSLTest.setup();
            Assert.fail("Expected ExceptionInInitializerError not thrown");
        } catch (ExceptionInInitializerError expected) {
            Assert.assertNotNull(expected);
        } finally {
            if (engine != null) {
                System.setProperty(SSL.ORG_WILDFLY_OPENSSL_ENGINE, engine);
            } else {
                System.clearProperty(SSL.ORG_WILDFLY_OPENSSL_ENGINE);
            }
        }
    }

    @Test
    public void secondTestRDRANDEngine() {
        String engine = System.setProperty(SSL.ORG_WILDFLY_OPENSSL_ENGINE, "rdrand");
        try {
            AbstractOpenSSLTest.setup();
            SSL ssl = SSL.getInstance();
            Assert.assertNotNull(ssl.version());
        } finally {
            if (engine != null) {
                System.setProperty(SSL.ORG_WILDFLY_OPENSSL_ENGINE, engine);
            } else {
                System.clearProperty(SSL.ORG_WILDFLY_OPENSSL_ENGINE);
            }
        }
    }
}

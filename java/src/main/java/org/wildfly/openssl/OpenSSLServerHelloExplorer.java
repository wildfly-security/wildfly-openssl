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

import java.nio.ByteBuffer;

/**
 */
final class OpenSSLServerHelloExplorer {

    // Private constructor prevents construction outside this class.
    private OpenSSLServerHelloExplorer() {
    }

    static int getCipherSuite(ByteBuffer input) {

        // What is the handshake type?
        byte messageType = input.get();
        if (messageType != 22) {   // handshake message
            return -1;
        }
        byte helloMajorVersion = input.get();
        byte helloMinorVersion = input.get();
        int length = getInt16(input);
        byte handshakeType = input.get();
        if(handshakeType != 2) {
            return -1;
        }

        // What is the handshake body length?
        int handshakeLength = getInt24(input);
        int result =  exploreServerHello(input);
        return result;
    }

    private static int exploreServerHello(ByteBuffer input) {

        // server version
        byte helloMajorVersion = input.get();
        byte helloMinorVersion = input.get();

        for (int i = 0; i < 32; ++i) { //the Random is 32 bytes
            input.get();
        }

        // ignore session id
        processByteVector8(input);

        // get cipher_suite
        return getInt16(input);
    }

    private static int getInt8(ByteBuffer input) {
        return input.get();
    }

    private static int getInt16(ByteBuffer input) {
        return (input.get() & 0xFF) << 8 | input.get() & 0xFF;
    }

    private static int getInt24(ByteBuffer input) {
        return (input.get() & 0xFF) << 16 | (input.get() & 0xFF) << 8 |
                input.get() & 0xFF;
    }

    private static void processByteVector8(ByteBuffer input) {
        int int8 = getInt8(input);
        processByteVector(input, int8);
    }


    private static void processByteVector(ByteBuffer input, int length) {
        for (int i = 0; i < length; ++i) {
            input.get();
        }
    }
}

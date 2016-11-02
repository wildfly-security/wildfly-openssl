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

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Stuart Douglas
 */
class OpenSSLInputStream extends InputStream {

    private final OpenSSLSocket socket;

    OpenSSLInputStream(OpenSSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public int read() throws IOException {
        return socket.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return socket.read(b, off, len);
    }

    @Override
    public int read(byte[] b) throws IOException {
        return socket.read(b, 0, b.length);
    }
}

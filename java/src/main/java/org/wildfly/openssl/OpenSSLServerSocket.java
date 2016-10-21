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
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLServerSocket;

/**
 * @author Stuart Douglas
 */
public class OpenSSLServerSocket extends SSLServerSocket {

    private final OpenSSLContextSPI openSSLContextSPI;

    public OpenSSLServerSocket(OpenSSLContextSPI openSSLContextSPI) throws IOException {
        this.openSSLContextSPI = openSSLContextSPI;
    }

    public OpenSSLServerSocket(int port, OpenSSLContextSPI openSSLContextSPI) throws IOException {
        super(port);
        this.openSSLContextSPI = openSSLContextSPI;
    }

    public OpenSSLServerSocket(int port, int backlog, OpenSSLContextSPI openSSLContextSPI) throws IOException {
        super(port, backlog);
        this.openSSLContextSPI = openSSLContextSPI;
    }

    public OpenSSLServerSocket(int port, int backlog, InetAddress bindAddr, OpenSSLContextSPI openSSLContextSPI) throws IOException {
        super(port, backlog, bindAddr);
        this.openSSLContextSPI = openSSLContextSPI;
    }

    @Override
    public Socket accept() throws IOException {
        final Socket delegate = super.accept();
        return new OpenSSLSocket(delegate, true, (OpenSSLEngine) openSSLContextSPI.createSSLEngine());
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return null;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return OpenSSLContextSPI.getAvailableCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {

    }

    @Override
    public void setNeedClientAuth(boolean need) {

    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {

    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setUseClientMode(boolean mode) {

    }

    @Override
    public boolean getUseClientMode() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {

    }

    @Override
    public boolean getEnableSessionCreation() {
        return false;
    }


}

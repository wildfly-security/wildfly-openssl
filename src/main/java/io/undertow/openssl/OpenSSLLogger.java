/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.undertow.openssl;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.nio.ByteBuffer;

/**
 * @author Stuart Douglas
 */
@MessageLogger(projectCode = "OPENSSL")
public interface OpenSSLLogger extends BasicLogger {

    OpenSSLLogger ROOT_LOGGER = Logger.getMessageLogger(OpenSSLLogger.class, OpenSSLLogger.class.getPackage().getName());

    @Message(id = 1, value = "engine.engineClosed")
    SSLException engineClosed();

    @Message(id = 2, value = "engine.renegociationUnsupported")
    SSLException renegotiationUnsupported();

    @Message(id = 3, value = "engine.oversizedPacket")
    SSLException oversizedPacket();

    @Message(id = 4, value = "engine.noSSLContext")
    IllegalStateException noSSLContext();

    @Message(id = 5, value = "engine.writeToSSLFailed")
    IllegalStateException writeToEngineFailed(int sslWrote);

    @Message(id = 6, value = "Buffer is null")
    IllegalArgumentException nullBuffer();

    @Message(id = 7, value = "Inbound is closed")
    SSLException inboundClosed();

    @Message(id = 8, value = "Null cypher suites")
    IllegalArgumentException nullCypherSuites();

    @Message(id = 9, value = "Unverified Peer")
    SSLPeerUnverifiedException unverifiedPeer();

    @Message(id = 10, value = "Session was invalid")
    IllegalStateException noSession();

    @Message(id = 11, value = "Name was null")
    IllegalArgumentException nullName();

    @Message(id = 12, value = "Value was null")
    IllegalArgumentException nullValue();

    @Message(id = 13, value = "Unsupported protocol %s")
    IllegalArgumentException unsupportedProtocol(String p);

    @Message(id = 14, value = "Empty cypher suite list")
    IllegalArgumentException emptyCypherSuiteList();

    @Message(id = 15, value = "Failed cypher suite %s")
    IllegalStateException failedCypherSuite(@Cause Exception e, String cipherSuiteSpec);

    @Message(id = 16, value = "Invalid offest (%s) and length (%s) into buffer array of length (%s)")
    IndexOutOfBoundsException invalidBufferIndex(int offset, int length, int dlength);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 17, value = "Failed to initialize ciphers")
    void ciphersFailure(@Cause Exception e);

    @Message(id = 18, value = "null ticket keys")
    IllegalArgumentException nullTicketKeys();
}

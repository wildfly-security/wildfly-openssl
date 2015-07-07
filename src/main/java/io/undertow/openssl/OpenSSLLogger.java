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

import static org.jboss.logging.Logger.Level.WARN;

/**
 * @author Stuart Douglas
 */
@MessageLogger(projectCode = "OPENSSL")
public interface OpenSSLLogger extends BasicLogger {

    OpenSSLLogger ROOT_LOGGER = Logger.getMessageLogger(OpenSSLLogger.class, OpenSSLLogger.class.getPackage().getName());

    @Message(id = 1, value = "Engine is closed")
    SSLException engineClosed();

    @Message(id = 2, value = "Renegotiation is not supported")
    SSLException renegotiationUnsupported();

    @Message(id = 3, value = "Oversized packet")
    SSLException oversizedPacket();

    @Message(id = 4, value = "No SSL Context")
    IllegalStateException noSSLContext();

    @Message(id = 5, value = "Write to SSL failed. Error code %s")
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

    @LogMessage(level = WARN)
    @Message(id = 17, value = "Failed to initialize ciphers")
    void ciphersFailure(@Cause Exception e);

    @Message(id = 18, value = "null ticket keys")
    IllegalArgumentException nullTicketKeys();

    @Message(id = 19, value = "Invalid option %s")
    IllegalArgumentException invalidOption(String value);

    @Message(id = 20, value = "Null private key file")
    IllegalArgumentException nullPrivateKeyFile();

    @Message(id = 21, value = "Null certificate chain")
    IllegalArgumentException nullCertificateChain();

    @LogMessage(level = WARN)
    @Message(id = 22, value = "File %s does not exist")
    void fileDoesNotExist(String newPath);

    @Message(id = 23, value = "Trust manager is missing")
    IllegalStateException trustManagerMissing();

    @Message(id = 24, value = "Trust manager is missing")
    IllegalStateException keyManagerMissing();

    @LogMessage(level = WARN)
    @Message(id = 25, value = "The version of SSL in use does not support cipher ordering")
    void noHonorCipherOrder();

    @LogMessage(level = WARN)
    @Message(id = 26, value = "The version of SSL in use does not support disabling compression")
    void noDisableCompression();

    @LogMessage(level = WARN)
    @Message(id = 27, value = "The version of SSL in use does not support disabling session tickets")
    void noDisableSessionTickets();

    @Message(id = 28, value = "Certificate file is null")
    SSLException certificateRequired();

    @LogMessage(level = WARN)
    @Message(id = 29, value = "Ignoring second invocation of init() method")
    void initCalledMultipleTimes();

    @Message(id = 30, value = "Invalid SSL protocol (%s)")
    SSLException invalidSSLProtocol(String protocol);

    @Message(id = 31, value = "Failed to make SSL context")
    SSLException failedToMakeSSLContext(@Cause Exception e);

    @Message(id = 32, value = "Failed to initialise OpenSSL context")
    SSLException failedToInitialiseSSLContext(@Cause Exception e);

    @LogMessage(level = WARN)
    @Message(id = 33, value = "Prefix missing when parsing SSL config hostname:%s string:%s")
    void prefixMissing(String trimmed, String hostName);

    @LogMessage(level = WARN)
    @Message(id = 35, value = "Unknown element %s")
    void unknownElement(String alias);

    @Message(id = 36, value = "could not find suitable trust manager")
    IllegalArgumentException couldNotFindSuitableKeyManger();

    @Message(id = 37, value = "KeyManager does not contain a valid certificates")
    IllegalStateException couldNotExtractAliasFromKeyManager();

    @Message(id = 38, value = "method not supported")
    UnsupportedOperationException unsupportedMethod();
}

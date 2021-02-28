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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Class that contains all native methods to interact with OpenSSL
 */
public abstract class SSL {

    private static final Logger logger = Logger.getLogger(SSL.class.getName());

    public static final String MAC_HOMEBREW_OPENSSL_PATH = "/usr/local/opt/openssl/lib/";
    private static SSL instance;

    public static final String ORG_WILDFLY_OPENSSL_PATH = "org.wildfly.openssl.path";
    public static final String ORG_WILDFLY_OPENSSL_PATH_LIBSSL = "org.wildfly.openssl.path.ssl";
    public static final String ORG_WILDFLY_OPENSSL_PATH_LIBCRYPTO = "org.wildfly.openssl.path.crypto";
    public static final String ORG_WILDFLY_LIBWFSSL_PATH = "org.wildfly.openssl.libwfssl.path";

    private static final String[] LIBCRYPTO_NAMES = {"crypto.1.1", "libcrypto-1_1-x64", "crypto", "libeay32", "libcrypto-1_1"};
    private static final String[] LIBSSL_NAMES = {"ssl.1.1", "libssl-1_1-x64", "ssl", "ssleay32", "libssl32", "libssl-1_1"};

    public SSL() {
    }

    private static Object holder;

    private static volatile boolean init = false;

    public static SSL getInstance() {
        init();
        return instance;
    }

    static void init() {
        if (!init) {
            synchronized (SSL.class) {
                if (!init) {
                    String libPath = System.getProperty(ORG_WILDFLY_LIBWFSSL_PATH);
                    if (libPath == null || libPath.isEmpty()) {
                        try {
                            System.loadLibrary("wfssl");
                            instance = new SSLImpl();
                        } catch (Throwable e) {
                            //try using out pre-packaged version
                            LibraryClassLoader libCl = new LibraryClassLoader(SSL.class.getClassLoader());
                            try {
                                Class loader = libCl.loadClass(LibraryLoader.class.getName());
                                Method load = loader.getDeclaredMethod("load");
                                Constructor ctor = loader.getDeclaredConstructor();
                                ctor.setAccessible(true);
                                load.setAccessible(true);
                                load.invoke(holder = ctor.newInstance());
                                Class sslClass = libCl.loadClass(SSLImpl.class.getName());
                                instance = (SSL) sslClass.newInstance();

                            } catch (Exception e1) {
                                throw new RuntimeException(e1);
                            }
                        }
                    } else {
                        Runtime.getRuntime().load(libPath);
                        instance = new SSLImpl();
                    }
                    String specifiedPath = System.getProperty(ORG_WILDFLY_OPENSSL_PATH);

                    if (specifiedPath != null && specifiedPath.isEmpty()) {
                        specifiedPath = null;
                    }
                    if (specifiedPath != null && !specifiedPath.endsWith(File.separator)) {
                        specifiedPath = specifiedPath + File.separator;
                    }
                    //mac OS ships with an old version of OpenSSL by default that we know won't work
                    //as a workaround we look for the one installed by brew instead
                    //so the oder goes:
                    //1) user specified location
                    //2) homebrew default location
                    //3) system default
                    String path = specifiedPath;
                    if (path == null) {
                        String os = System.getProperty("os.name").toLowerCase();
                        if (os.contains("mac")) {
                            File file = new File(MAC_HOMEBREW_OPENSSL_PATH);
                            if (file.exists()) {
                                path = MAC_HOMEBREW_OPENSSL_PATH;
                            }
                        }
                    }
                    String sslPath = System.getProperty(ORG_WILDFLY_OPENSSL_PATH_LIBSSL);
                    String cryptoPath = System.getProperty(ORG_WILDFLY_OPENSSL_PATH_LIBCRYPTO);
                    List<String> paths = new ArrayList<>();
                    if (specifiedPath != null) {
                        paths.add(specifiedPath);
                    } else {
                        if (path != null) {
                            paths.add(path);
                        }
                        for (String p : System.getProperty("java.library.path").split(File.pathSeparator)) {
                            if (p != null) {
                                paths.add(p);
                            }
                        }
                    }
                    List<String> attemptedSSL = new ArrayList<>();
                    List<String> attemptedCrypto = new ArrayList<>();
                    VersionedLibrary sslVersion = null;
                    for (String p : paths) {
                        if (sslPath != null && cryptoPath != null) {
                            break;
                        }
                        if (sslPath == null) {
                            for (String ssl : LIBSSL_NAMES) {
                                String lib = System.mapLibraryName(ssl);
                                File file = new File(p, lib);
                                if (file.exists()) {
                                    sslPath = file.getAbsolutePath();
                                    break;
                                }
                                attemptedSSL.add(file.getAbsolutePath());
                            }
                            if (sslPath == null) {
                                for (String ssl : LIBSSL_NAMES) {
                                    String lib = System.mapLibraryName(ssl);
                                    sslVersion = searchForVersionedLibrary(p, lib, null);
                                    if (sslVersion != null) {
                                        sslPath = sslVersion.file;
                                        break;
                                    }
                                }
                            }
                        }
                        if (sslPath != null) {
                            for (String crypto : LIBCRYPTO_NAMES) {
                                String lib = System.mapLibraryName(crypto);
                                File file = new File(p, lib);
                                if (file.exists()) {
                                    cryptoPath = file.getAbsolutePath();
                                    break;
                                }
                                attemptedCrypto.add(file.getAbsolutePath());
                            }
                            if (cryptoPath == null && sslVersion != null) {
                                for (String crypto : LIBCRYPTO_NAMES) {
                                    String lib = System.mapLibraryName(crypto);
                                    VersionedLibrary cryptoVersion = searchForVersionedLibrary(p, lib, sslVersion.versionPart);
                                    if (cryptoVersion != null) {
                                        cryptoPath = cryptoVersion.file;
                                        break;
                                    }
                                }
                            }
                            if (cryptoPath == null) {
                                //we need them to match, if we find one but not the other we look elsewhere
                                sslPath = null;
                                sslVersion = null;
                            }
                        }
                    }
                    if (sslPath == null) {
                        throw new RuntimeException(Messages.MESSAGES.couldNotFindLibSSL(ORG_WILDFLY_OPENSSL_PATH, attemptedSSL.toString()));
                    }
                    if (cryptoPath == null) {
                        throw new RuntimeException(Messages.MESSAGES.couldNotFindLibCrypto(ORG_WILDFLY_OPENSSL_PATH, attemptedCrypto.toString()));
                    }
                    instance.initialize(cryptoPath, sslPath);
                    String version = instance.version();
                    logger.info(Messages.MESSAGES.openSSLVersion(version));


                    init = true;
                }
            }
        }
    }

    private static VersionedLibrary searchForVersionedLibrary(String path, String lib, String requiredVersion) {
        File file = new File(path);
        String[] files = file.list();
        List<VersionedLibrary> versionedLibraries = new ArrayList<>();
        if (files != null) {
            for (String test : files) {
                if (test.startsWith(lib)) {
                    String absolutePath = new File(path, test).getAbsolutePath();
                    String versionedPart = test.substring(lib.length());
                    if (requiredVersion != null && versionedPart.equals(requiredVersion)) {
                        return new VersionedLibrary(absolutePath, versionedPart);
                    } else {
                        versionedLibraries.add(new VersionedLibrary(absolutePath, versionedPart));
                    }
                }
            }
        }
        if (versionedLibraries.isEmpty()) {
            return null;
        }
        Collections.sort(versionedLibraries);
        return versionedLibraries.get(0);
    }

    private static final class LibraryClassLoader extends ClassLoader {

        LibraryClassLoader(ClassLoader parent) {
            super(parent);
        }

        @Override
        protected String findLibrary(String libname) {
            final String mapped = System.mapLibraryName(libname);
            for (String path : Identification.NATIVE_SEARCH_PATHS) {
                String complete = path + "/" + mapped;
                try {
                    try (InputStream resource = SSL.class.getClassLoader().getResourceAsStream(complete)) {
                        if (resource != null) {
                            File temp = File.createTempFile("tmp-", "openssl");
                            temp.delete();
                            temp.mkdir();
                            File result = new File(temp, mapped);
                            try (FileOutputStream out = new FileOutputStream(result)) {
                                byte[] buf = new byte[1000];
                                int r;
                                while ((r = resource.read(buf)) > 0) {
                                    out.write(buf, 0, r);
                                }
                            }
                            result.deleteOnExit();
                            temp.deleteOnExit();
                            return result.getAbsolutePath();
                        }
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return super.findLibrary(libname);
        }

        @Override
        public Class<?> loadClass(String name) throws ClassNotFoundException {
            if (!name.endsWith("$LibraryLoader") && !name.endsWith(".SSLImpl")) {
                return getParent().loadClass(name);
            }
            try (InputStream file = SSL.class.getClassLoader().getResourceAsStream(name.replace(".", "/") + ".class")) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[1024];
                int r;
                while ((r = file.read(buf)) > 0) {
                    out.write(buf, 0, r);
                }
                byte[] data = out.toByteArray();
                return defineClass(name, data, 0, data.length, SSL.class.getProtectionDomain());
            } catch (IOException e) {
                throw new ClassNotFoundException(e.getMessage());
            }
        }
    }

    static class LibraryLoader {
        public void load() {
            System.loadLibrary("wfssl");
        }
    }

    protected abstract void initialize(String libCryptoPath, String libSslPath);

    /**
     * JSSE and OpenSSL protocol names
     */
    static final String SSL_PROTO_ALL = "all";
    static final String SSL_PROTO_TLS = "TLS";
    static final String SSL_PROTO_TLSv1_3 = "TLSv1.3";
    static final String SSL_PROTO_TLSv1_2 = "TLSv1.2";
    static final String SSL_PROTO_TLSv1_1 = "TLSv1.1";
    static final String SSL_PROTO_TLSv1 = "TLSv1";
    static final String SSL_PROTO_SSLv3 = "SSLv3";
    static final String SSL_PROTO_SSLv2 = "SSLv2";
    static final String SSL_PROTO_SSLv2Hello = "SSLv2Hello";

    /*
     * Type definitions mostly from mod_ssl
     */
    static final int UNSET = -1;
    /*
     * Define the certificate algorithm types
     */
    static final int SSL_ALGO_UNKNOWN = 0;
    static final int SSL_ALGO_RSA = (1 << 0);
    static final int SSL_ALGO_DSA = (1 << 1);
    static final int SSL_ALGO_ALL = (SSL_ALGO_RSA | SSL_ALGO_DSA);

    static final int SSL_AIDX_RSA = 0;
    static final int SSL_AIDX_DSA = 1;
    static final int SSL_AIDX_ECC = 3;
    static final int SSL_AIDX_MAX = 4;
    /*
     * Define IDs for the temporary RSA keys and DH params
     */

    static final int SSL_TMP_KEY_RSA_512 = 0;
    static final int SSL_TMP_KEY_RSA_1024 = 1;
    static final int SSL_TMP_KEY_RSA_2048 = 2;
    static final int SSL_TMP_KEY_RSA_4096 = 3;
    static final int SSL_TMP_KEY_DH_512 = 4;
    static final int SSL_TMP_KEY_DH_1024 = 5;
    static final int SSL_TMP_KEY_DH_2048 = 6;
    static final int SSL_TMP_KEY_DH_4096 = 7;
    static final int SSL_TMP_KEY_MAX = 8;

    /*
     * Define the SSL options
     */
    static final int SSL_OPT_NONE = 0;
    static final int SSL_OPT_RELSET = (1 << 0);
    static final int SSL_OPT_STDENVVARS = (1 << 1);
    static final int SSL_OPT_EXPORTCERTDATA = (1 << 3);
    static final int SSL_OPT_FAKEBASICAUTH = (1 << 4);
    static final int SSL_OPT_STRICTREQUIRE = (1 << 5);
    static final int SSL_OPT_OPTRENEGOTIATE = (1 << 6);
    static final int SSL_OPT_ALL = (SSL_OPT_STDENVVARS | SSL_OPT_EXPORTCERTDATA | SSL_OPT_FAKEBASICAUTH | SSL_OPT_STRICTREQUIRE | SSL_OPT_OPTRENEGOTIATE);

    /*
     * Define the SSL Protocol options
     */
    static final int SSL_PROTOCOL_NONE = 0;
    static final int SSL_PROTOCOL_SSLV2 = (1 << 0);
    static final int SSL_PROTOCOL_SSLV3 = (1 << 1);
    static final int SSL_PROTOCOL_TLSV1 = (1 << 2);
    static final int SSL_PROTOCOL_TLSV1_1 = (1 << 3);
    static final int SSL_PROTOCOL_TLSV1_2 = (1 << 4);
    static final int SSL_PROTOCOL_TLSV1_3 = (1 << 5);
    static final int SSL_PROTOCOL_ALL = (SSL_PROTOCOL_TLSV1 | SSL_PROTOCOL_TLSV1_1 | SSL_PROTOCOL_TLSV1_2 | SSL_PROTOCOL_TLSV1_3);

    /*
     * Define the SSL verify levels
     */
    static final int SSL_CVERIFY_UNSET = UNSET;
    static final int SSL_CVERIFY_NONE = 0;
    static final int SSL_CVERIFY_OPTIONAL = 1;
    static final int SSL_CVERIFY_REQUIRE = 2;
    static final int SSL_CVERIFY_OPTIONAL_NO_CA = 3;

    /* Use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 2 options
     * are 'ored' with SSL_VERIFY_PEER if they are desired
     */
    static final int SSL_VERIFY_NONE = 0;
    static final int SSL_VERIFY_PEER = 1;
    static final int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2;
    static final int SSL_VERIFY_CLIENT_ONCE = 4;
    static final int SSL_VERIFY_PEER_STRICT = (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);

    static final int SSL_OP_MICROSOFT_SESS_ID_BUG = 0x00000001;
    static final int SSL_OP_NETSCAPE_CHALLENGE_BUG = 0x00000002;
    static final int SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008;
    static final int SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00000010;
    static final int SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00000020;
    static final int SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x00000040;
    static final int SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 0x00000080;
    static final int SSL_OP_TLS_D5_BUG = 0x00000100;
    static final int SSL_OP_TLS_BLOCK_PADDING_BUG = 0x00000200;

    /* Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
     * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
     * the workaround is not needed.  Unfortunately some broken SSL/TLS
     * implementations cannot handle it at all, which is why we include
     * it in SSL_OP_ALL. */
    static final int SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800;

    /* SSL_OP_ALL: various bug workarounds that should be rather harmless.
     *             This used to be 0x000FFFFFL before 0.9.7. */
    static final int SSL_OP_ALL = 0x00000FFF;
    /* As server, disallow session resumption on renegotiation */
    static final int SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000;
    /* Don't use compression even if supported */
    static final int SSL_OP_NO_COMPRESSION = 0x00020000;
    /* Permit unsafe legacy renegotiation */
    static final int SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00040000;
    /* If set, always create a new key when using tmp_eddh parameters */
    static final int SSL_OP_SINGLE_ECDH_USE = 0x00080000;
    /* If set, always create a new key when using tmp_dh parameters */
    static final int SSL_OP_SINGLE_DH_USE = 0x00100000;
    /* Set to always use the tmp_rsa key when doing RSA operations,
     * even when this violates protocol specs */
    static final int SSL_OP_EPHEMERAL_RSA = 0x00200000;
    /* Set on servers to choose the cipher according to the server's
     * preferences */
    static final int SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000;
    /* If set, a server will allow a client to issue a SSLv3.0 version number
     * as latest version supported in the premaster secret, even when TLSv1.0
     * (version 3.1) was announced in the client hello. Normally this is
     * forbidden to prevent version rollback attacks. */
    static final int SSL_OP_TLS_ROLLBACK_BUG = 0x00800000;

    static final int SSL_OP_NO_SSLv2 = 0x01000000;
    static final int SSL_OP_NO_SSLv3 = 0x02000000;
    static final int SSL_OP_NO_TLSv1 = 0x04000000;
    static final int SSL_OP_NO_TLSv1_3 = 0x20000000;
    static final int SSL_OP_NO_TLSv1_2 = 0x08000000;
    static final int SSL_OP_NO_TLSv1_1 = 0x10000000;

    static final int SSL3_VERSION = 0x0300;
    static final int TLS1_VERSION = 0x0301;
    static final int TLS1_1_VERSION = 0x0302;
    static final int TLS1_2_VERSION = 0x0303;
    static final int TLS1_3_VERSION = 0x0304;

    static final int SSL_OP_NO_TICKET = 0x00004000;

    // SSL_OP_PKCS1_CHECK_1 and SSL_OP_PKCS1_CHECK_2 flags are unsupported
    // in the current version of OpenSSL library. See ssl.h changes in commit
    // 7409d7ad517650db332ae528915a570e4e0ab88b (30 Apr 2011) of OpenSSL.
    /**
     * @deprecated Unsupported in the current version of OpenSSL
     */
    @Deprecated
    static final int SSL_OP_PKCS1_CHECK_1 = 0x08000000;
    /**
     * @deprecated Unsupported in the current version of OpenSSL
     */
    @Deprecated
    static final int SSL_OP_PKCS1_CHECK_2 = 0x10000000;
    static final int SSL_OP_NETSCAPE_CA_DN_BUG = 0x20000000;
    static final int SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000;

    static final int SSL_CRT_FORMAT_UNDEF = 0;
    static final int SSL_CRT_FORMAT_ASN1 = 1;
    static final int SSL_CRT_FORMAT_TEXT = 2;
    static final int SSL_CRT_FORMAT_PEM = 3;
    static final int SSL_CRT_FORMAT_NETSCAPE = 4;
    static final int SSL_CRT_FORMAT_PKCS12 = 5;
    static final int SSL_CRT_FORMAT_SMIME = 6;
    static final int SSL_CRT_FORMAT_ENGINE = 7;

    static final int SSL_MODE_CLIENT = 0;
    static final int SSL_MODE_SERVER = 1;
    static final int SSL_MODE_COMBINED = 2;

    static final int SSL_SHUTDOWN_TYPE_UNSET = 0;
    static final int SSL_SHUTDOWN_TYPE_STANDARD = 1;
    static final int SSL_SHUTDOWN_TYPE_UNCLEAN = 2;
    static final int SSL_SHUTDOWN_TYPE_ACCURATE = 3;

    static final int SSL_INFO_SESSION_ID = 0x0001;
    static final int SSL_INFO_CIPHER = 0x0002;
    static final int SSL_INFO_CIPHER_USEKEYSIZE = 0x0003;
    static final int SSL_INFO_CIPHER_ALGKEYSIZE = 0x0004;
    static final int SSL_INFO_CIPHER_VERSION = 0x0005;
    static final int SSL_INFO_CIPHER_DESCRIPTION = 0x0006;
    static final int SSL_INFO_PROTOCOL = 0x0007;

    /* To obtain the CountryName of the Client Certificate Issuer
     * use the SSL_INFO_CLIENT_I_DN + SSL_INFO_DN_COUNTRYNAME
     */
    static final int SSL_INFO_CLIENT_S_DN = 0x0010;
    static final int SSL_INFO_CLIENT_I_DN = 0x0020;
    static final int SSL_INFO_SERVER_S_DN = 0x0040;
    static final int SSL_INFO_SERVER_I_DN = 0x0080;

    static final int SSL_INFO_DN_COUNTRYNAME = 0x0001;
    static final int SSL_INFO_DN_STATEORPROVINCENAME = 0x0002;
    static final int SSL_INFO_DN_LOCALITYNAME = 0x0003;
    static final int SSL_INFO_DN_ORGANIZATIONNAME = 0x0004;
    static final int SSL_INFO_DN_ORGANIZATIONALUNITNAME = 0x0005;
    static final int SSL_INFO_DN_COMMONNAME = 0x0006;
    static final int SSL_INFO_DN_TITLE = 0x0007;
    static final int SSL_INFO_DN_INITIALS = 0x0008;
    static final int SSL_INFO_DN_GIVENNAME = 0x0009;
    static final int SSL_INFO_DN_SURNAME = 0x000A;
    static final int SSL_INFO_DN_DESCRIPTION = 0x000B;
    static final int SSL_INFO_DN_UNIQUEIDENTIFIER = 0x000C;
    static final int SSL_INFO_DN_EMAILADDRESS = 0x000D;

    static final int SSL_INFO_CLIENT_M_VERSION = 0x0101;
    static final int SSL_INFO_CLIENT_M_SERIAL = 0x0102;
    static final int SSL_INFO_CLIENT_V_START = 0x0103;
    static final int SSL_INFO_CLIENT_V_END = 0x0104;
    static final int SSL_INFO_CLIENT_A_SIG = 0x0105;
    static final int SSL_INFO_CLIENT_A_KEY = 0x0106;
    static final int SSL_INFO_CLIENT_CERT = 0x0107;
    static final int SSL_INFO_CLIENT_V_REMAIN = 0x0108;

    static final int SSL_INFO_SERVER_M_VERSION = 0x0201;
    static final int SSL_INFO_SERVER_M_SERIAL = 0x0202;
    static final int SSL_INFO_SERVER_V_START = 0x0203;
    static final int SSL_INFO_SERVER_V_END = 0x0204;
    static final int SSL_INFO_SERVER_A_SIG = 0x0205;
    static final int SSL_INFO_SERVER_A_KEY = 0x0206;
    static final int SSL_INFO_SERVER_CERT = 0x0207;
    /* Return client certificate chain.
     * Add certificate chain number to that flag (0 ... verify depth)
     */
    static final int SSL_INFO_CLIENT_CERT_CHAIN = 0x0400;

    static final long SSL_SESS_CACHE_OFF = 0x0000;
    static final long SSL_SESS_CACHE_CLIENT = 0x0001;
    static final long SSL_SESS_CACHE_SERVER = 0x0002;

    static final int SSL_SELECTOR_FAILURE_NO_ADVERTISE = 0;
    static final int SSL_SELECTOR_FAILURE_CHOOSE_MY_LAST_PROTOCOL = 1;

    static final long VERSION_1_1_0 = 0x10100000L;
    static final long VERSION_1_1_0_F = 0x1010006fL;
    static final long VERSION_1_1_1 = 0x10101000L;

    /* Return OpenSSL version number */
    protected abstract String version();

    /**
     * Return true if all the requested SSL_OP_* are supported by OpenSSL.
     * <p>
     * <i>Note that for versions of tcnative &lt; 1.1.25, this method will
     * return <code>true</code> if and only if <code>op</code>=
     * {@link #SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION} and tcnative
     * supports that flag.</i>
     *
     * @param op Bitwise-OR of all SSL_OP_* to test.
     * @return true if all SSL_OP_* are supported by OpenSSL library.
     */
    protected abstract boolean hasOp(int op);

    /*
     * Begin Twitter API additions
     */

    static final int SSL_SENT_SHUTDOWN = 1;
    static final int SSL_RECEIVED_SHUTDOWN = 2;

    static final int SSL_ERROR_NONE = 0;
    static final int SSL_ERROR_SSL = 1;
    static final int SSL_ERROR_WANT_READ = 2;
    static final int SSL_ERROR_WANT_WRITE = 3;
    static final int SSL_ERROR_WANT_X509_LOOKUP = 4;
    static final int SSL_ERROR_SYSCALL = 5; /* look at error stack/return value/errno */
    static final int SSL_ERROR_ZERO_RETURN = 6;
    static final int SSL_ERROR_WANT_CONNECT = 7;
    static final int SSL_ERROR_WANT_ACCEPT = 8;

    /**
     * SSL_new
     *
     * @param ctx    Server or Client context to use.
     * @param server if true configure SSL instance to use accept handshake routines
     *               if false configure SSL instance to use connect handshake routines
     * @return pointer to SSL instance (SSL *)
     */
    protected abstract long newSSL(long ctx, boolean server);

    /**
     * BIO_ctrl_pending.
     *
     * @param bio BIO pointer (BIO *)
     */
    protected abstract int pendingWrittenBytesInBIO(long bio);

    /**
     * SSL_pending.
     *
     * @param ssl SSL pointer (SSL *)
     */
    protected abstract int pendingReadableBytesInSSL(long ssl);

    /**
     * BIO_write.
     *
     * @param bio
     * @param wbuf
     * @param wlen
     */
    protected abstract int writeToBIO(long bio, long wbuf, int wlen);

    /**
     * BIO_read.
     *
     * @param bio
     * @param rbuf
     * @param rlen
     */
    protected abstract int readFromBIO(long bio, long rbuf, int rlen);

    /**
     * SSL_write.
     *
     * @param ssl  the SSL instance (SSL *)
     * @param wbuf
     * @param wlen
     */
    protected abstract int writeToSSL(long ssl, long wbuf, int wlen);

    /**
     * SSL_read
     *
     * @param ssl  the SSL instance (SSL *)
     * @param rbuf
     * @param rlen
     */
    protected abstract int readFromSSL(long ssl, long rbuf, int rlen);

    /**
     * SSL_get_shutdown
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract int getShutdown(long ssl);

    /**
     * SSL_free
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract void freeSSL(long ssl);

    /**
     * Wire up internal and network BIOs for the given SSL instance.
     * <p>
     * <b>Warning: you must explicitly free this resource by calling freeBIO</b>
     * <p>
     * While the SSL's internal/application data BIO will be freed when freeSSL is called on
     * the provided SSL instance, you must call freeBIO on the returned network BIO.
     *
     * @param ssl the SSL instance (SSL *)
     * @return pointer to the Network BIO (BIO *)
     */
    protected abstract long makeNetworkBIO(long ssl);

    /**
     * BIO_free
     *
     * @param bio
     */
    protected abstract void freeBIO(long bio);

    /**
     * SSL_shutdown
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract int shutdownSSL(long ssl);

    /**
     * Get the error number representing the last error OpenSSL encountered on
     * this thread.
     */
    protected abstract int getLastErrorNumber();

    /**
     * SSL_get_cipher.
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract String getCipherForSSL(long ssl);

    /**
     * SSL_get_version
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract String getVersion(long ssl);

    /**
     * Return OpenSSL version number.
     * @return the version number
     */
    protected abstract long versionNumber();

    /**
     * SSL_do_handshake
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract int doHandshake(long ssl);

    protected abstract int getSSLError(long ssl, int code);

    protected abstract void saveServerCipher(long ssl, int cipher);

    /**
     * SSL_renegotiate
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract int renegotiate(long ssl);

    /**
     * SSL_in_init.
     *
     * @param SSL
     */
    protected abstract int isInInit(long SSL);

    /**
     * SSL_get0_alpn_selected
     *
     * @param ssl the SSL instance (SSL *)
     */
    protected abstract String getAlpnSelected(long ssl);

    /**
     * enables ALPN on the server side
     */
    protected abstract void enableAlpn(long ssl);

    protected abstract boolean isAlpnSupported();

    /**
     * Get the peer certificate chain or {@code null} if non was send.
     */
    protected abstract byte[][] getPeerCertChain(long ssl);

    /**
     * Get the peer certificate or {@code null} if non was send.
     */
    protected abstract byte[] getPeerCertificate(long ssl);

    /*
     * Get the error number representing for the given {@code errorNumber}.
     */
    protected abstract String getErrorString(long errorNumber);

    /**
     * SSL_get_time
     *
     * @param ssl the SSL instance (SSL *)
     * @return returns the time at which the session ssl was established. The time is given in seconds since the Epoch
     */
    protected abstract long getTime(long ssl);

    /**
     * Set Type of Client Certificate verification and Maximum depth of CA Certificates
     * in Client Certificate verification.
     * <br />
     * This directive sets the Certificate verification level for the Client
     * Authentication. Notice that this directive can be used both in per-server
     * and per-directory context. In per-server context it applies to the client
     * authentication process used in the standard SSL handshake when a connection
     * is established. In per-directory context it forces a SSL renegotiation with
     * the reconfigured client verification level after the HTTP request was read
     * but before the HTTP response is sent.
     * <br />
     * The following levels are available for level:
     * <pre>
     * SSL_CVERIFY_NONE           - No client Certificate is required at all
     * SSL_CVERIFY_OPTIONAL       - The client may present a valid Certificate
     * SSL_CVERIFY_REQUIRE        - The client has to present a valid Certificate
     * SSL_CVERIFY_OPTIONAL_NO_CA - The client may present a valid Certificate
     *                              but it need not to be (successfully) verifiable
     * </pre>
     * <br />
     * The depth actually is the maximum number of intermediate certificate issuers,
     * i.e. the number of CA certificates which are max allowed to be followed while
     * verifying the client certificate. A depth of 0 means that self-signed client
     * certificates are accepted only, the default depth of 1 means the client
     * certificate can be self-signed or has to be signed by a CA which is directly
     * known to the server (i.e. the CA's certificate is under
     * {@code setCACertificatePath}, etc.
     *
     * @param ssl   the SSL instance (SSL *)
     * @param level Type of Client Certificate verification.
     * @param depth Maximum depth of CA Certificates in Client Certificate
     *              verification.
     */
    protected abstract void setSSLVerify(long ssl, int level, int depth);

    /**
     * Set OpenSSL Option.
     *
     * @param ssl     the SSL instance (SSL *)
     * @param options See SSL.SSL_OP_* for option flags.
     */
    protected abstract void setOptions(long ssl, long options);

    /**
     * Get OpenSSL Option.
     *
     * @param ssl the SSL instance (SSL *)
     * @return options  See SSL.SSL_OP_* for option flags.
     */
    protected abstract long getOptions(long ssl);

    /**
     * Returns all Returns the cipher suites that are available for negotiation in an SSL handshake.
     *
     * @param ssl the SSL instance (SSL *)
     * @return ciphers
     */
    protected abstract String[] getCiphers(long ssl);

    /**
     * Returns the cipher suites available for negotiation in SSL handshake.
     * <br />
     * This complex directive uses a colon-separated cipher-spec string consisting
     * of OpenSSL cipher specifications to configure the Cipher Suite the client
     * is permitted to negotiate in the SSL handshake phase. Notice that this
     * directive can be used both in per-server and per-directory context.
     * In per-server context it applies to the standard SSL handshake when a
     * connection is established. In per-directory context it forces a SSL
     * renegotiation with the reconfigured Cipher Suite after the HTTP request
     * was read but before the HTTP response is sent.
     *
     * @param ssl     the SSL instance (SSL *)
     * @param ciphers an SSL cipher specification
     */
    protected abstract boolean setCipherSuites(long ssl, String ciphers)
            throws Exception;

    /**
     * Sets the cipher suites available for negotiation in the SSL handshake.
     * <br />
     * This is a simple colon (":") separated list of TLSv1.3 ciphersuite names in order of preference.
     *
     * @param ssl     the SSL instance (SSL *)
     * @param ciphers an SSL cipher specification
     */
    protected abstract boolean setCipherSuitesTLS13(long ssl, String ciphers)
            throws Exception;

    protected abstract boolean setServerNameIndication(long ssl,
                                                       String hostName);

    /**
     * Returns the pointer reference to the SSL session.
     * <a href="https://www.openssl.org/docs/manmaster/ssl/SSL_get_session.html">https://www.openssl.org/docs/manmaster/ssl/SSL_get_session.html</a>
     * <p>
     * This uses the {@code SSL_get1_session()}. The {@link #invalidateSession(long)} SSL_SESSION_free} needs to
     * explicitly be called once to decrement the reference count.
     * </p>
     * <p>
     * From the OpenSSL documentation:
     * <blockquote>
     * If the data is to be kept, SSL_get1_session() will increment the reference count, so that the session will
     * not be implicitly removed by other operations but stays in memory. In order to remove the session
     * {@code SSL_SESSION_free} must be explicitly called once to decrement the reference count again.
     * </blockquote>
     * </p>
     *
     * @param ssl the SSL instance (SSL *)
     * @return the pointer reference to the SSL session
     */
    protected abstract long getSession(long ssl);

    /**
     * Sets the session for the SSL instance.
     * <a href="https://www.openssl.org/docs/manmaster/ssl/SSL_set_session.html">https://www.openssl.org/docs/manmaster/ssl/SSL_set_session.html</a>
     *
     * @param ssl     the SSL instance (SSL *)
     * @param session the pointer to the SSL session to set the SSL instance to
     */
    protected abstract void setSession(long ssl, long session);

    /**
     * Returns the ID of the session as byte array representation.
     *
     * @param ssl the SSL instance (SSL *)
     * @return the session as byte array representation obtained via SSL_SESSION_get_id.
     */
    protected abstract byte[] getSessionId(long ssl);

    protected abstract long bufferAddress(ByteBuffer buffer);


    /**
     * Create a new SSL context.
     *
     * @param protocol The SSL protocol to use. It can be any combination of
     *                 the following:
     *                 <PRE>
     *                 {@link SSL#SSL_PROTOCOL_SSLV2}
     *                 {@link SSL#SSL_PROTOCOL_SSLV3}
     *                 {@link SSL#SSL_PROTOCOL_TLSV1}
     *                 {@link SSL#SSL_PROTOCOL_TLSV1_1}
     *                 {@link SSL#SSL_PROTOCOL_TLSV1_2}
     *                 {@link SSL#SSL_PROTOCOL_TLSV1_3}
     *                 {@link SSL#SSL_PROTOCOL_ALL} ( == all TLS versions, no SSL)
     *                 </PRE>
     * @param mode     SSL mode to use
     *                 <PRE>
     *                 SSL_MODE_CLIENT
     *                 SSL_MODE_SERVER
     *                 SSL_MODE_COMBINED
     *                 </PRE>
     * @return The Java representation of a pointer to the newly created SSL
     * Context
     * @throws Exception If the SSL Context could not be created
     */
    protected abstract long makeSSLContext(int protocol, int mode) throws Exception;

    /**
     * Free the resources used by the Context
     *
     * @param ctx Server or Client context to free.
     * @return APR Status code.
     */
    protected abstract int freeSSLContext(long ctx);

    /**
     * Set OpenSSL Option.
     *
     * @param ctx     Server or Client context to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    protected abstract void setSSLContextOptions(long ctx, long options);

    /**
     * Clears OpenSSL Options.
     *
     * @param ctx     Server or Client context to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    protected abstract void clearSSLContextOptions(long ctx, long options);

    /**
     * Set OpenSSL Option.
     *
     * @param ssl     Server or Client SSL to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    protected abstract void setSSLOptions(long ssl, long options);

    /**
     * Clears OpenSSL Options.
     *
     * @param ssl     Server or Client SSL to use.
     * @param options See SSL.SSL_OP_* for option flags.
     */
    protected abstract void clearSSLOptions(long ssl, long options);

    /**
     * Cipher Suite available for negotiation in SSL handshake.
     * <br>
     * This complex directive uses a colon-separated cipher-spec string consisting
     * of OpenSSL cipher specifications to configure the Cipher Suite the client
     * is permitted to negotiate in the SSL handshake phase. Notice that this
     * directive can be used both in per-server and per-directory context.
     * In per-server context it applies to the standard SSL handshake when a
     * connection is established. In per-directory context it forces a SSL
     * renegotiation with the reconfigured Cipher Suite after the HTTP request
     * was read but before the HTTP response is sent.
     *
     * @param ctx     Server or Client context to use.
     * @param ciphers An SSL cipher specification.
     */
    protected abstract boolean setCipherSuite(long ctx, String ciphers)
            throws Exception;

    /**
     * Sets the cipher suites available for negotiation in the SSL handshake.
     * <br />
     * This is a simple colon (":") separated list of TLSv1.3 ciphersuite names in order of preference.
     *
     * @param ctx     Server or Client context to use.
     * @param ciphers an SSL cipher specification
     */
    protected abstract boolean setCipherSuiteTLS13(long ctx, String ciphers)
            throws Exception;

    /**
     * Set File of concatenated PEM-encoded CA CRLs or
     * directory of PEM-encoded CA Certificates for Client Auth
     * <br>
     * This directive sets the all-in-one file where you can assemble the
     * Certificate Revocation Lists (CRL) of Certification Authorities (CA)
     * whose clients you deal with. These are used for Client Authentication.
     * Such a file is simply the concatenation of the various PEM-encoded CRL
     * files, in order of preference.
     * <br>
     * The files in this directory have to be PEM-encoded and are accessed through
     * hash filenames. So usually you can't just place the Certificate files there:
     * you also have to create symbolic links named hash-value.N. And you should
     * always make sure this directory contains the appropriate symbolic links.
     * Use the Makefile which comes with mod_ssl to accomplish this task.
     *
     * @param ctx  Server or Client context to use.
     * @param file File of concatenated PEM-encoded CA CRLs for Client Auth.
     * @param path Directory of PEM-encoded CA Certificates for Client Auth.
     */
    protected abstract boolean setCARevocation(long ctx, String file,
                                               String path)
            throws Exception;

    /**
     * Set Certificate
     * <br>
     * Point setCertificateFile at a PEM encoded certificate.  If
     * the certificate is encrypted, then you will be prompted for a
     * pass phrase.  Note that a kill -HUP will prompt again. A test
     * certificate can be generated with `make certificate' under
     * built time. Keep in mind that if you've both a RSA and a DSA
     * certificate you can configure both in parallel (to also allow
     * the use of DSA ciphers, etc.)
     * <br>
     * If the key is not combined with the certificate, use key param
     * to point at the key file.  Keep in mind that if
     * you've both a RSA and a DSA private key you can configure
     * both in parallel (to also allow the use of DSA ciphers, etc.)
     *  @param ctx  Server or Client context to use.
     * @param cert Certificate file.
     * @param encodedIntermediaries
     * @param key  Private Key file to use if not in cert.
     * @param idx  Certificate index SSL_AIDX_RSA or SSL_AIDX_DSA.
     */
    protected abstract boolean setCertificate(long ctx, byte[] cert,
                                              byte[][] encodedIntermediaries, byte[] key,
                                              int idx)
            throws Exception;

    /**
     * Set the size of the internal session cache.
     * http://www.openssl.org/docs/ssl/SSL_CTX_sess_set_cache_size.html
     */
    protected abstract long setSessionCacheSize(long ctx, long size);

    /**
     * Get the size of the internal session cache.
     * http://www.openssl.org/docs/ssl/SSL_CTX_sess_get_cache_size.html
     */
    protected abstract long getSessionCacheSize(long ctx);

    /**
     * Set the timeout for the internal session cache in seconds.
     * http://www.openssl.org/docs/ssl/SSL_CTX_set_timeout.html
     */
    protected abstract long setSessionCacheTimeout(long ctx, long timeoutSeconds);

    /**
     * Get the timeout for the internal session cache in seconds.
     * http://www.openssl.org/docs/ssl/SSL_CTX_set_timeout.html
     */
    protected abstract long getSessionCacheTimeout(long ctx);

    /**
     * Set the mode of the internal session cache and return the previous used mode.
     */
    protected abstract long setSessionCacheMode(long ctx, long mode);

    /**
     * Get the mode of the current used internal session cache.
     */
    protected abstract long getSessionCacheMode(long ctx);

    /**
     * Session resumption statistics methods.
     * http://www.openssl.org/docs/ssl/SSL_CTX_sess_number.html
     */
    protected abstract long sessionAccept(long ctx);

    protected abstract long sessionAcceptGood(long ctx);

    protected abstract long sessionAcceptRenegotiate(long ctx);

    protected abstract long sessionCacheFull(long ctx);

    protected abstract long sessionCbHits(long ctx);

    protected abstract long sessionConnect(long ctx);

    protected abstract long sessionConnectGood(long ctx);

    protected abstract long sessionConnectRenegotiate(long ctx);

    protected abstract long sessionHits(long ctx);

    protected abstract long sessionMisses(long ctx);

    protected abstract long sessionNumber(long ctx);

    protected abstract long sessionTimeouts(long ctx);

    /**
     * Set TLS session keys. This allows us to share keys across TFEs.
     */
    protected abstract void setSessionTicketKeys(long ctx, byte[] keys);

    /**
     * When tc-native encounters a SNI extension in the TLS handshake it will
     * call this method to determine which OpenSSL SSLContext to use for the
     * connection.
     *
     * @param currentCtx  The OpenSSL SSLContext that the handshake started to
     *                    use. This will be the default OpenSSL SSLContext for
     *                    the endpoint associated with the socket.
     * @param sniHostName The host name requested by the client
     * @return The Java representation of the pointer to the OpenSSL SSLContext
     * to use for the given host or zero if no SSLContext could be
     * identified
     */
    static long sniCallBack(long currentCtx, String sniHostName) {
        SNICallBack sniCallBack = sniCallBacks.get(Long.valueOf(currentCtx));
        if (sniCallBack == null) {
            return currentCtx;
        }
        return sniCallBack.getSslContext(sniHostName);
    }

    /*
     * A map of default SSL Contexts to SNICallBack instances (in Tomcat these
     * are instances of AprEndpoint) that will be used to determine the SSL
     * Context to use bases on the SNI host name. It is structured this way
     * since a Tomcat instance may have several TLS enabled endpoints that each
     * have different SSL Context mappings for the same host name.
     */
    private static Map<Long, SNICallBack> sniCallBacks = new ConcurrentHashMap<>();

    /**
     * Register an OpenSSL SSLContext that will be used to initiate TLS
     * connections that may use the SNI extension with the component that will
     * be used to map the requested hostname to the correct OpenSSL SSLContext
     * for the remainder of the connection.
     *
     * @param defaultSSLContext The Java representation of a pointer to the
     *                          OpenSSL SSLContext that will be used to
     *                          initiate TLS connections
     * @param sniCallBack       The component that will map SNI hosts names received
     *                          via connections initiated using
     *                          <code>defaultSSLContext</code> to the correct  OpenSSL
     *                          SSLContext
     */
    static void registerDefault(Long defaultSSLContext,
                                SNICallBack sniCallBack) {
        sniCallBacks.put(defaultSSLContext, sniCallBack);
    }

    /**
     * Unregister an OpenSSL SSLContext that will no longer be used to initiate
     * TLS connections that may use the SNI extension.
     *
     * @param defaultSSLContext The Java representation of a pointer to the
     *                          OpenSSL SSLContext that will no longer be used
     */
    static void unregisterDefault(Long defaultSSLContext) {
        sniCallBacks.remove(defaultSSLContext);
    }

    /**
     * invalidates the current SSL session
     */
    protected abstract void invalidateSession(long ctx);

    protected abstract void registerSessionContext(long context, OpenSSLSessionContext openSSLSessionContext);

    /**
     * Interface implemented by components that will receive the call back to
     * select an OpenSSL SSLContext based on the host name requested by the
     * client.
     */
    interface SNICallBack {

        /**
         * This callback is made during the TLS handshake when the client uses
         * the SNI extension to request a specific TLS host.
         *
         * @param sniHostName The host name requested by the client
         * @return The Java representation of the pointer to the OpenSSL
         * SSLContext to use for the given host or zero if no SSLContext
         * could be identified
         */
        long getSslContext(String sniHostName);
    }

    /**
     * Allow to hook {@link CertificateVerifier} into the handshake processing.
     * This will call {@code SSL_CTX_set_cert_verify_callback} and so replace the default verification
     * callback used by openssl
     *
     * @param ctx      Server or Client context to use.
     * @param verifier the verifier to call during handshake.
     */
    protected abstract void setCertVerifyCallback(long ctx, CertificateVerifier verifier);

    /**
     * Set application layer protocol for application layer protocol negotiation extension.
     * <p>
     * This should only be called by the client.
     *
     * @param ssl        SSL Engine to use
     * @param alpnProtos protocols in priority order
     */
    protected abstract void setAlpnProtos(long ssl, String[] alpnProtos);

    /**
     * Sets the server ALPN callback for a spcific engine
     *
     * @param ssl      The SSL engine
     * @param callback the callbackto use
     */
    protected abstract void setServerALPNCallback(long ssl, ServerALPNCallback callback);

    /**
     * Set the context within which session be reused (server side only)
     * http://www.openssl.org/docs/ssl/SSL_CTX_set_session_id_context.html
     *
     * @param ctx    Server context to use.
     * @param sidCtx can be any kind of binary data, it is therefore possible to use e.g. the name
     *               of the application and/or the hostname and/or service name
     * @return {@code true} if success, {@code false} otherwise.
     */
    protected abstract boolean setSessionIdContext(long ctx, byte[] sidCtx);

    /**
     * Set the minimum supported protocol version. This will call {@code SSL_set_min_proto_version}.
     * See https://www.openssl.org/docs/manmaster/man3/SSL_set_min_proto_version.html.
     *
     * @param ssl the SSL engine
     * @param version the minimum supported protocol version
     */
    protected abstract void setMinProtoVersion(long ssl, int version);

    /**
     * Set the maximum supported protocol version. This will call {@code SSL_set_max_proto_version}.
     * See https://www.openssl.org/docs/manmaster/man3/SSL_set_max_proto_version.html.
     *
     * @param ssl the SSL engine
     * @param version the maximum supported protocol version
     */
    protected abstract void setMaxProtoVersion(long ssl, int version);

    /**
     * Get the minimum supported protocol version. This will call {@code SSL_get_min_proto_version}.
     * See https://www.openssl.org/docs/manmaster/man3/SSL_get_min_proto_version.html.
     *
     * @param ssl the SSL engine
     * @return the minimum supported protocol version
     */
    protected abstract int getMinProtoVersion(long ssl);

    /**
     * Get the maximum supported protocol version. This will call {@code SSL_get_max_proto_version}.
     * See https://www.openssl.org/docs/manmaster/man3/SSL_get_max_proto_version.html.
     *
     * @param ssl the SSL engine
     * @return the maximum supported protocol version
     */
    protected abstract int getMaxProtoVersion(long ssl);

    /**
     * Return whether or not the SSL session was reused.
     * See https://www.openssl.org/docs/man1.1.1/man3/SSL_session_reused.html
     * @param ssl the SSL engine
     * @return {@code true} if the SSL session was reused and {@code false} otherwise
     */
    protected abstract boolean getSSLSessionReused(long ssl);

    private static final class VersionedLibrary implements Comparable<VersionedLibrary> {
        final String file;
        final String versionPart;

        private VersionedLibrary(String file, String versionPart) {
            this.file = file;
            this.versionPart = versionPart;
        }

        @Override
        public int compareTo(VersionedLibrary versionedLibrary) {
            //fairly hacky, but naming schemes are not consistent
            //we want to prefer the newer openssl 1.1, but the old real way to sort
            //this properly is just to look for the 1.1 string
            boolean other11 = versionedLibrary.versionPart.contains("1.1");
            boolean this11 = versionPart.contains("1.1");
            if(other11 && !this11) {
                return 1;
            } else if(!other11 && this11) {
                return -1;
            }
            return versionedLibrary.versionPart.compareTo(versionPart);
        }
    }
}

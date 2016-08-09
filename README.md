OpenSSL Bindings for Java
=========================

This project provides OpenSSL bindings for Java. As much as possible they attempt to use existing JSSE API's, so the
SSLContext should be usable as a drop in replacement for applications that are currently using JSSE.

Usage
=====

Registering the provider
------------------------

These bindings are implemented as a security provider. By default the provider will not be installed, so the easiest way
to install the provider is to call `org.wildfly.openssl.OpenSSLProvider.register()`.

Note that at the moment this project does not provide signed jars (this may change in the future). If you wish to register
this as a default provider you will need to sign the jar yourself.

Installing the native library
-----------------------------

There are two different native libraries that must be loaded, the `libwfssl` binary provided by this project, and OpenSSL
itself. `libwfssl` is loaded through a standard java.lang.System.loadLibrary() invocation, so should be located somewhere
where it can be discovered by the JVM. Alternatively you can specify the `org.wildfly.openssl.libwfssl.path` system property
to specify the full path to the `libwfssl` library.

OpenSSL is loaded dynamically, and its location can be specified by the `org.wildfly.openssl.path` system property. If
this property is not present the standard system library search path with be used instead. Because the library is loaded
dynamically it should be possible to use different versions of OpenSSL without needed to recompile.

Using the provider
------------------

After the provider has been registered all that is necessary to use it to get the SSLContext:

    SSLContext sslContext =  SSLContext.getInstance("openssl.TLSv1");

The SSLContext can then be used as normal, and should provide a drop in replacement for JSSE.

Building
========

The java side of the project uses maven and can be build as normal (`mvn install`). The native code uses cmake to provide
a platform independent build. To build the native code cd into the `libwfssl` directory and issue the following commands:

    cmake CMakeLists.txt
    make

For the windows build the actual command to use will depend on the compiler you wish to use, but for visual studio it
will probably be:

     cmake CMakeLists.txt -G "Visual Studio 14 2015"

See the complete list of cmake generators at https://cmake.org/cmake/help/v3.1/manual/cmake-generators.7.html .

OpenSSL Bindings for Java
=========================

This project provides OpenSSL bindings for Java. As much as possible they attempt to use existing JSSE API's, so the
SSLContext should be usable as a drop in replacement for applications that are currently using JSSE.

This code was originally based on the Tomcat Native code, however it has been fairly extensively modified to more closely
align with JSSE and to support dynamic linking.

Usage
=====

Maven artifact
--------------

There are two Maven artifacts to choose between, which one you use will depend on your use case:


        <dependency>
            <groupId>org.wildfly.openssl</groupId>
            <artifactId>wildfly-openssl-java</artifactId>
            <version>${project.version}</version>
        </dependency>
        
        <dependency>
            <groupId>org.wildfly.openssl</groupId>
            <artifactId>wildfly-openssl</artifactId>
            <version>${project.version}</version>
        </dependency>

The `wildfly-openssl-java` artifact does not contain any native code. To use it you will need to either place the native library
somewhere that it can be found by `System.loadLibrary`, or include a maven artifact that has the library packaged (such as one of
the platform specific artifacts built by this project).

The `wildfly-openssl` artifact contains binaries for Mac, Linux and Windows (all for x86_64). If no other version of these
 native libraries is found then these will be extracted to a temporary directory and loaded. This should allow it to run without
 having to worry about how to deal with the native code.


Registering the provider
------------------------

These bindings are implemented as a security provider. By default the provider will not be installed, so the easiest way
to install the provider is to call `org.wildfly.openssl.OpenSSLProvider.register()`.

Note that at the moment this project does not provide signed jars (this may change in the future). If you wish to register
this as a default provider you will need to sign the jar yourself.

Installing the native library
-----------------------------

If you are running on x86_64 Mac, Windows or Linux then you can use the out of the box support provided by the `wildfly-openssl`
artifact.

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

    SSLContext sslContext =  SSLContext.getInstance("openssl.TLS");

The SSLContext can then be used as normal, and should provide a drop in replacement for JSSE.

Building
========

The java side of the project uses maven and can be build as normal (`mvn install`). The native code should be build
as part of the standard build process.

### Windows

To do the Windows build you need to run the build from a visual studio native tools command prompt. If you want to build
the 32 bit natives you must use the 32 bit prompt (and have JAVA_HOME pointed to a 32 bit JVM), otherwise both the prompt
and the JVM must be 64 bit.

#### Configuring Your Environment

1. Visit the [OpenSSL Wiki](https://wiki.openssl.org/index.php/Binaries) and choose where to download OpenSSL
   from.
    * Install OpenSSL, ideally both 32 and 64 bit versions.
        * When prompted install the executables in the `C:\OpenSSL-32\bin` and `C:\OpenSSL-64\bin` directories
          respectively.
    * _Optional:_ Configure a `OPENSSL_32` and `OPENSSL_64` permanent environment variable.
    
1. Next ensure you have both a 32 and 64 bit JDK installed.
    * You can download OpenJDK from [Red Hat](https://developers.redhat.com/products/openjdk/download)
    * It seems to be easiest to download the zips.
        * For example unzip to `%USERPROFILE%\apps` and rename the directory to something simple like `java-1.8.0`.

1. Download and install [Visual Studio](https://visualstudio.microsoft.com/downloads/).
    * Make sure you install the native tools for the command prompt too.
    
#### Building 32-bit Natives

Navigate to the `x86 Native Tools Command Prompt for VS 2019` executable. Generally you can navigate to this through
the start menu. For Visual Studio 2019 Community the location is 
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2019\Visual Studio Tools\VC`.

Once the command prompt is open make sure you set your `JAVA_HOME` to the 32-bit JDK. Then update the `INCLUDE`
environment variable to include the OpenSSL headers.

Example:
```
cd %USERPROFILE%\projects\wildfly-openssl
set "JAVA_HOME=%USERPROFILE%\apps\java-1.8.0-32"
set "INCLUDE=%INCLUDE%;%OPENSSL_32%\include"
mvn clean install
```

#### Building 64-bit Natives

Navigate to the `x64 Native Tools Command Prompt for VS 2019` executable. Generally you can navigate to this through
the start menu. For Visual Studio 2019 Community the location is 
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2019\Visual Studio Tools\VC`.

Once the command prompt is open make sure you set your `JAVA_HOME` to the 64-bit JDK. Then update the `INCLUDE`
environment variable to include the OpenSSL headers.

Example:
```
cd %USERPROFILE%\projects\wildfly-openssl
set "JAVA_HOME=%USERPROFILE%\apps\java-1.8.0"
set "INCLUDE=%INCLUDE%;%OPENSSL_64%\include"
mvn clean install
```

Contributions
-------------

Our [contribution guide](https://github.com/wildfly-security/wildfly-openssl/blob/master/CONTRIBUTING.md) will guide you 
through the steps for getting started on the WildFly OpenSSL project and will go through how to format and submit your first PR.

For more details, check out our [getting started guide](https://wildfly-security.github.io/wildfly-elytron/getting-started-for-developers/) for developers.

.SUFFIXES: .dll

all: target\classes\win-i686\wfssl.dll
OBJECTS = target\alpn.obj target\clientcert.obj target\options.obj target\session.obj target\ssl.obj target\threads.obj target\util.obj

{../libwfssl/src}.c{target}.obj:
    cl /TC $<  /Fo$@ -I..\libwfssl\include -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" /LD /c

target:
  mkdir target

target\classes: target
  mkdir target\classes

target\classes\win-i686: target\classes
  mkdir target\classes\win-i686

target\classes\win-i686\wfssl.dll: target\classes\win-i686 $(OBJECTS)
   link $(OBJECTS)  /DLL -out:target\classes\win-i686\wfssl.dll

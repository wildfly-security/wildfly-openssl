.SUFFIXES: .dll

all: wfssl.dll
OBJECTS = alpn.obj clientcert.obj options.obj session.obj ssl.obj threads.obj util.obj

{../libwfssl/src}.c.obj::
    cl $< -I../libwfssl/include -I$(JAVA_HOME)/include -IC:\OpenSSL-Win64\include /LD


wfssl.dll  : $(OBJECTS)
   link $(OBJECTS)  /machine:AMD64 /DLL -out:wfssl.dll


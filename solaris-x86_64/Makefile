CC = gcc
SRC = alpn.c clientcert.c options.c session.c ssl.c threads.c util.c
OBJ = $(patsubst %.c, target/%.o, $(SRC))

default: target/classes/solaris-x86_64/libwfssl.so

clean:
	rm -rf target
target/classes/solaris-x86_64:
	mkdir -p target/classes/solaris-x86_64

target/alpn.o : ../libwfssl/src/alpn.c target/classes/solaris-x86_64
	$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/solaris

target/clientcert.o : ../libwfssl/src/clientcert.c target/classes/solaris-x86_64
	$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/solaris

target/options.o : ../libwfssl/src/options.c target/classes/solaris-x86_64
	$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/solaris

target/session.o : ../libwfssl/src/session.c target/classes/solaris-x86_64
	$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/solaris

target/ssl.o : ../libwfssl/src/ssl.c target/classes/solaris-x86_64
	$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/solaris

target/threads.o : ../libwfssl/src/threads.c target/classes/solaris-x86_64
	$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/solaris

target/util.o : ../libwfssl/src/util.c target/classes/solaris-x86_64
	$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/solaris

target/classes/solaris-x86_64/libwfssl.so: $(OBJ)
	$(CC) $(CFLAGS) -m64 -shared $(OBJ) -o $@ $(LDFLAGS) -ldl

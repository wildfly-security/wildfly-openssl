
SRC = alpn.c clientcert.c options.c session.c ssl.c threads.c util.c
OBJ = $(patsubst %.c, target/%.o, $(SRC))

default: target/classes/libwfssl.so

clean:
	rm -rf target

target/classes:
	mkdir -p target/classes
	

target/%.o : ../libwfssl/src/%.c target/classes
	cc -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

target/classes/libwfssl.so: $(OBJ)
	cc -shared $(OBJ) -o $@ -Wl,--no-as-needed -ldl

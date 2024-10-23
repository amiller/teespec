tls_test: tls_test.c
	clang -Os -g -o tls_test tls_test.c \
	    -lmbedtls -lmbedx509 -lmbedcrypto

clean:
	rm tls_test

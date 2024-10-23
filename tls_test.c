#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <string.h>

int main(void) {
    mbedtls_net_context server;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_sha256_context sha;
    unsigned char hash[32];
    unsigned char buf[1024];
    
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_net_init(&server);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_sha256_init(&sha);
    
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_setup(&ssl, &conf);
    
    mbedtls_net_connect(&server, "example.com", "443", MBEDTLS_NET_PROTO_TCP);
    mbedtls_ssl_set_bio(&ssl, &server, mbedtls_net_send, mbedtls_net_recv, NULL);
    mbedtls_ssl_handshake(&ssl);
    
    mbedtls_ssl_write(&ssl, (unsigned char *)"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 40);
    
    // Updated SHA256 API usage
    mbedtls_sha256_starts_ret(&sha, 0);
    
    int len;
    while((len = mbedtls_ssl_read(&ssl, buf, sizeof(buf))) > 0)
        mbedtls_sha256_update_ret(&sha, buf, len);
    
    mbedtls_sha256_finish_ret(&sha, hash);
    
    for(int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");
    
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_sha256_free(&sha);
    
    return 0;
}

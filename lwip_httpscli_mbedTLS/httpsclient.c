/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2017 NXP. Not a Contribution
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/sockets.h"
#include "httpsclient.h"
#include "lwip/netdb.h"
#include "fsl_debug_console.h"
#include <stdlib.h>
#include <stdio.h>

#include "memfault/components.h"
#include "memfault/http/root_certs.h"

const char memfault_cert[] = MEMFAULT_ROOT_CERTS_DIGICERT_GLOBAL_ROOT_CA;

// Memfault project key
const char *memfault_project_key = "<YOUR PROJECT KEY HERE>";

// Switch this to get verbose debug prints
#define DEBUG_PRINTF(...)
// #define DEBUG_PRINTF(...) PRINTF(__VA_ARGS__)

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 10
#define GET_REQUEST                                           \
    "GET /media/uploads/mbed_official/hello.txt HTTP/1.0\r\n" \
    "HOST: os.mbed.com\r\n\r\n"

#define DEBUG_LEVEL 0

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
TLSDataParams tlsDataParams;
const char *HTTPS_SERVER_NAME = MEMFAULT_HTTP_CHUNKS_API_HOST;
const char *HTTPS_SERVER_PORT = "443";
unsigned char https_buf[1024];
/*******************************************************************************
 * Code
 ******************************************************************************/

/* Send function used by mbedtls ssl */
static int lwipSend(void *fd, unsigned char const *buf, size_t len)
{
    return lwip_send((*(int *)fd), buf, len, 0);
}

/* Send function used by mbedtls ssl */
static int lwipRecv(void *fd, unsigned char const *buf, size_t len)
{
    return lwip_recv((*(int *)fd), (void *)buf, len, 0);
}

int write_request(void *chunk_data, size_t chunk_data_len)
{
    /*
     * Write the POST request
     */
    int ret = 0;

    // format string for building the HTTP header
#define POST_REQUEST                                                           \
  "POST /api/v0/chunks/TESTSERIAL HTTP/1.1\r\n"                                \
  "Host:chunks.memfault.com\r\n"                                               \
  "User-Agent: MemfaultSDK/0.4.2\r\n"                                          \
  "Memfault-Project-Key:%s\r\n"                                                \
  "Content-Type:application/octet-stream\r\n"                                  \
  "Content-Length:%d\r\n\r\n"


    // format the request
    unsigned char sendbuf[1048];
    size_t len = sprintf((char *)sendbuf, POST_REQUEST, memfault_project_key,
                         chunk_data_len);

    DEBUG_PRINTF( "  > Write to server:" );

    DEBUG_PRINTF("\nHeader: \n%s", sendbuf);

    // send the header
    while( ( ret = mbedtls_ssl_write( &(tlsDataParams.ssl), sendbuf, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            PRINTF( "\n failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    DEBUG_PRINTF( "\n %d header bytes written\n\n", len);

    // send the payload
    while ((ret = mbedtls_ssl_write(&(tlsDataParams.ssl),
                                    (const unsigned char *)chunk_data,
                                    chunk_data_len)) <= 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        PRINTF(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
        goto exit;
      }
    }

    len = ret;
    DEBUG_PRINTF(" %d bytes written\n\n%s", len, (char *)https_buf);

    return ret;

exit:
    https_client_tls_release();
    return -1;
}

int read_request(void)
{
    /*
     * Read the HTTPS response
     */
    int ret = 0;
    int len = 0;
    DEBUG_PRINTF("  < Read from server:");

    do
    {
        len = sizeof(https_buf) - 1;
        memset(https_buf, 0, sizeof(https_buf));
        ret = mbedtls_ssl_read(&(tlsDataParams.ssl), https_buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            break;

        if (ret < 0)
        {
            PRINTF("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
            goto exit;
        }

        if (ret == 0)
        {
            DEBUG_PRINTF("\n\nEOF\n\n");
            break;
        }

        len = ret;
        DEBUG_PRINTF(" %d bytes read\n\n%s", len, (char *)https_buf);

        // the connection doesn't hang up until 30 seconds after the HTTP
        // request completes, so check for an HTTP response code
        if (strstr(https_buf, "HTTP/1.1 ")) {
            DEBUG_PRINTF("  . Response received, exiting\n");
            break;
        }
    } while (1);

    if (strstr(https_buf, "HTTP/1.1 202 Accepted")) {
        PRINTF("  < HTTP 202 Accepted received!\n");
        ret = 0;
    } else {
        PRINTF(" HTTP Response error:\n%s\n", https_buf);
        ret = -1;
    }

    return ret;

exit:
    https_client_tls_release();
    return -1;
}

static int _iot_tls_verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    char buf[1024];
    ((void)data);

    DEBUG_PRINTF("\nVerify requested for (Depth %d):\n", depth);
    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
    DEBUG_PRINTF("%s", buf);

    if ((*flags) == 0)
    {
        DEBUG_PRINTF("  This certificate has no flags\n");
    }
    else
    {
        DEBUG_PRINTF(buf, sizeof(buf), "  ! ", *flags);
        DEBUG_PRINTF("%s\n", buf);
    }

    return 0;
}

#ifdef MBEDTLS_DEBUG_C
static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);

    DEBUG_PRINTF("\r\n%s, at line %d in file %s\n", str, line, file);
}
#endif

int https_client_tls_init(void)
{
    int ret          = 0;
    const char *pers = "aws_iot_tls_wrapper";
    char vrfy_buf[512];
    bool ServerVerificationFlag = false;
    const mbedtls_md_info_t *md_info;

#ifdef MBEDTLS_DEBUG_C
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
#endif

    mbedtls_ssl_init(&(tlsDataParams.ssl));
    mbedtls_ssl_config_init(&(tlsDataParams.conf));
    mbedtls_hmac_drbg_init(&(tlsDataParams.hmac_drbg));
    mbedtls_x509_crt_init(&(tlsDataParams.cacert));
    mbedtls_x509_crt_init(&(tlsDataParams.clicert));
    mbedtls_pk_init(&(tlsDataParams.pkey));

#if defined(MBEDTLS_DEBUG_C)
    /* Enable debug output of mbedtls */
    mbedtls_ssl_conf_dbg(&(tlsDataParams.conf), my_debug, NULL);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    DEBUG_PRINTF("\n  . Seeding the random number generator...");
    mbedtls_entropy_init(&(tlsDataParams.entropy));
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if ((ret = mbedtls_hmac_drbg_seed(&(tlsDataParams.hmac_drbg), md_info, mbedtls_entropy_func,
                                      &(tlsDataParams.entropy), (const unsigned char *)pers, strlen(pers))) != 0)
    {
        PRINTF(" failed\n  ! mbedtls_hmac_drbg_seed returned -0x%x\n", -ret);
        return NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }

    DEBUG_PRINTF("  . Loading the CA root certificate ...");
    ret = mbedtls_x509_crt_parse(&(tlsDataParams.cacert), (const unsigned char *)mbedtls_test_ca_crt,
                                 mbedtls_test_ca_crt_len);
    if (ret < 0)
    {
        PRINTF(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\n\n", -ret);
        return NETWORK_X509_ROOT_CRT_PARSE_ERROR;
    }
    DEBUG_PRINTF(" ok (%d skipped)\n", ret);

    DEBUG_PRINTF("  . Loading the client cert. and key...");
    ret = mbedtls_x509_crt_parse(&(tlsDataParams.clicert), (const unsigned char *)mbedtls_test_cli_crt,
                                 mbedtls_test_cli_crt_len);
    if (ret != 0)
    {
        PRINTF(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing device cert\n\n", -ret);
        return NETWORK_X509_DEVICE_CRT_PARSE_ERROR;
    }

    ret = mbedtls_pk_parse_key(&(tlsDataParams.pkey), (const unsigned char *)mbedtls_test_cli_key,
                               mbedtls_test_cli_key_len, NULL, 0);
    if (ret != 0)
    {
        PRINTF(" failed\n  !  mbedtls_pk_parse_key returned -0x%x while parsing private key\n\n", -ret);
        return NETWORK_PK_PRIVATE_KEY_PARSE_ERROR;
    }
    DEBUG_PRINTF(" ok\n");
    PRINTF("Connecting to %s/%s ... ", HTTPS_SERVER_NAME, HTTPS_SERVER_PORT);

    struct addrinfo hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    ret = getaddrinfo(HTTPS_SERVER_NAME, HTTPS_SERVER_PORT, &hints, &res);
    if ((ret != 0) || (res == NULL))
    {
        return NETWORK_ERR_NET_UNKNOWN_HOST;
    }

    tlsDataParams.fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (tlsDataParams.fd < 0)
    {
        return NETWORK_ERR_NET_SOCKET_FAILED;
    }

    ret = connect(tlsDataParams.fd, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);

    if (ret != 0)
    {
        close(tlsDataParams.fd);
        return NETWORK_ERR_NET_CONNECT_FAILED;
    }

    DEBUG_PRINTF("  . Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&(tlsDataParams.conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        PRINTF(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
        return SSL_CONNECTION_ERROR;
    }

    mbedtls_ssl_conf_verify(&(tlsDataParams.conf), _iot_tls_verify_cert, NULL);
    if (ServerVerificationFlag == true)
    {
        mbedtls_ssl_conf_authmode(&(tlsDataParams.conf), MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    else
    {
        mbedtls_ssl_conf_authmode(&(tlsDataParams.conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    mbedtls_ssl_conf_rng(&(tlsDataParams.conf), mbedtls_hmac_drbg_random, &(tlsDataParams.hmac_drbg));

    mbedtls_ssl_conf_ca_chain(&(tlsDataParams.conf), &(tlsDataParams.cacert), NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams.conf), &(tlsDataParams.clicert), &(tlsDataParams.pkey))) != 0)
    {
        PRINTF(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        return SSL_CONNECTION_ERROR;
    }

    if ((ret = mbedtls_ssl_setup(&(tlsDataParams.ssl), &(tlsDataParams.conf))) != 0)
    {
        PRINTF(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        return SSL_CONNECTION_ERROR;
    }
    if ((ret = mbedtls_ssl_set_hostname(&(tlsDataParams.ssl), HTTPS_SERVER_NAME)) != 0)
    {
        PRINTF(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        return SSL_CONNECTION_ERROR;
    }
    DEBUG_PRINTF("\n\nSSL state connect : %d ", tlsDataParams.ssl.state);

    mbedtls_ssl_set_bio(&(tlsDataParams.ssl), &(tlsDataParams.fd), lwipSend, (mbedtls_ssl_recv_t *)lwipRecv, NULL);

    PRINTF(" ok\n");
    DEBUG_PRINTF("\n\nSSL state connect : %d ", tlsDataParams.ssl.state);
    DEBUG_PRINTF("  . Performing the SSL/TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&(tlsDataParams.ssl))) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            PRINTF(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
            {
                PRINTF(
                    "    Unable to verify the server's certificate. "
                    "    Alternatively, you may want to use "
                    "auth_mode=optional for testing purposes.\n");
            }
            return SSL_CONNECTION_ERROR;
        }
    }

    DEBUG_PRINTF(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n", mbedtls_ssl_get_version(&(tlsDataParams.ssl)),
           mbedtls_ssl_get_ciphersuite(&(tlsDataParams.ssl)));
    if ((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams.ssl))) >= 0)
    {
        DEBUG_PRINTF("    [ Record expansion is %d ]\n", ret);
    }
    else
    {
        DEBUG_PRINTF("    [ Record expansion is unknown (compression) ]\n");
    }

    DEBUG_PRINTF("  . Verifying peer X.509 certificate...");

    if (ServerVerificationFlag == true)
    {
        if ((tlsDataParams.flags = mbedtls_ssl_get_verify_result(&(tlsDataParams.ssl))) != 0)
        {
            PRINTF(" failed\n");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", tlsDataParams.flags);
            PRINTF("%s\n", vrfy_buf);
            ret = SSL_CONNECTION_ERROR;
        }
        else
        {
            DEBUG_PRINTF(" ok\n");
            ret = SUCCESS;
        }
    }
    else
    {
        DEBUG_PRINTF(" Server Verification skipped\n");
        ret = SUCCESS;
    }

#ifdef MBEDTLS_DEBUG_C
    if (mbedtls_ssl_get_peer_cert(&(tlsDataParams.ssl)) != NULL)
    {
        DEBUG_PRINTF("  . Peer certificate information    ...\n");
        mbedtls_x509_crt_info((char *)buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams.ssl)));
        DEBUG_PRINTF("%s\n", buf);
    }
#endif

    mbedtls_ssl_conf_read_timeout(&(tlsDataParams.conf), IOT_SSL_READ_TIMEOUT);

      // buffer to copy chunk data into
      while (memfault_packetizer_data_available()) {
        uint8_t buf[512];
        size_t buf_len = sizeof(buf);

        bool data_available = memfault_packetizer_get_chunk(buf, &buf_len);
        if (!data_available ) {
            return false; // no more data to send
        }

        // // example chunk data
        // const unsigned char chunk[] = {
        //     0x08, 0x02, 0xa7, 0x02, 0x01, 0x03, 0x01, 0x07, 0x6a, 0x54, 0x45,
        //     0x53, 0x54, 0x53, 0x45, 0x52, 0x49, 0x41, 0x4c, 0x0a, 0x6d, 0x74,
        //     0x65, 0x73, 0x74, 0x2d, 0x73, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72,
        //     0x65, 0x09, 0x6a, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x2d, 0x74, 0x65,
        //     0x73, 0x74, 0x06, 0x6d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x68, 0x61,
        //     0x72, 0x64, 0x77, 0x61, 0x72, 0x65, 0x04, 0xa1, 0x01, 0xa1, 0x72,
        //     0x63, 0x68, 0x75, 0x6e, 0x6b, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x5f,
        //     0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x01, 0x31, 0xe4};

        PRINTF("\nSending chunk of size %d\n", buf_len);
        ret = write_request(buf, buf_len);
        if (ret != buf_len) {
            PRINTF("Error! chunk write request failed\n");
            break;
        }

        ret = read_request();
                if (ret != 0) {
            PRINTF("Error! chunk write response failed\n");
            break;
        }
      }

    https_client_tls_release();
    return (Error_t)ret;
}

/* Release TLS */
void https_client_tls_release(void)
{
    close(tlsDataParams.fd);
    mbedtls_x509_crt_free(&(tlsDataParams.clicert));
    mbedtls_x509_crt_free(&(tlsDataParams.cacert));
    mbedtls_pk_free(&(tlsDataParams.pkey));
    mbedtls_ssl_free(&(tlsDataParams.ssl));
    mbedtls_ssl_config_free(&(tlsDataParams.conf));
    mbedtls_hmac_drbg_free(&(tlsDataParams.hmac_drbg));
    mbedtls_entropy_free(&(tlsDataParams.entropy));
}

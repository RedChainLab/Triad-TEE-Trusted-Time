/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include "sgx_ttls.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "utility.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include "sgx_urts.h"


/*
int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);*/
int read_from_session_peer(
    SSL*& ssl_session);
int read_from_session_peer_tsc(
    SSL*& ssl_session,
    int& count);
int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);

int write_to_session_peer_tsc(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length,
    int id_node);

sgx_status_t load_tls_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& certificate,
    EVP_PKEY*& pkey);

sgx_status_t initalize_ssl_context(SSL_CONF_CTX*& ssl_conf_ctx, SSL_CTX*& ctx);

/**
 * tee_get_self_signed_certificate
 *
 * This function generates a self-signed x.509 certificate.
 * This function only runs inside the enclave.
 *
 * @param[in] subject_name A string containing an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate.
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) for details.
 * Example value "CN=Intel SGX Enclave,O=Intel Corporation,C=US".
 *
 * @param[in] p_prv_key A private key used to sign this certificate.
 * @param[in] private_key_size The size of the private key in bytes.
 * @param[in] p_pub_key A public key used as the certificate's subject key.
 * @param[in] public_key_size The size of the public key in bytes.
 * @param[out] pp_output_cert A pointer to the output certificate pointer.
 * @param[out] p_output_cert_size A pointer to the size of the output certificate.
 *
 * @return SGX_SUCCESS on success.
 */

sgx_status_t SGXAPI tee_get_self_signed_certificate(
    const unsigned char *p_subject_name,
    const uint8_t *p_prv_key,
    size_t private_key_size,
    const uint8_t *p_pub_key,
    size_t public_key_size,
    uint8_t **pp_output_cert,
    size_t *p_output_cert_size);
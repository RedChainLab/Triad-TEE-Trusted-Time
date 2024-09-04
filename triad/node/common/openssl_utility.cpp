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

#include "openssl_utility.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void tee_free_certificate_mock(uint8_t *cert) {
    if (cert != NULL) {
        free(cert);
    }
}

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
 * @return SGX_QL_SUCCESS on success.
 */
sgx_status_t SGXAPI tee_get_self_signed_certificate(
    const unsigned char *p_subject_name,
    const uint8_t *p_prv_key,
    size_t private_key_size,
    const uint8_t *p_pub_key,
    size_t public_key_size,
    uint8_t **pp_output_cert,
    size_t *p_output_cert_size) {

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    int ret = 1;
    sgx_status_t result = SGX_SUCCESS;
    X509_NAME *name = NULL;
    EVP_PKEY *privkey = NULL;
    char *data_ptr = NULL;
    long data_len = 0;

    // Create a new X509 certificate
    x509 = X509_new();
    if (!x509) {
        goto cleanup;
    }

    // Set version to X509v3 (starts from 0)
    if (!X509_set_version(x509, 2)) {
        goto cleanup;
    }

    // Set the serial number (arbitrary value for self-signed cert)
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // Set the issuer name (same as subject for self-signed cert)
    name = X509_NAME_new();
    if (!name) {
        goto cleanup;
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, p_subject_name, -1, -1, 0)) {
        goto cleanup;
    }
    if (!X509_set_issuer_name(x509, name) || !X509_set_subject_name(x509, name)) {
        goto cleanup;
    }

    // Set the public key for the certificate
    bio = BIO_new_mem_buf(p_pub_key, public_key_size);
    if (!bio) {
        goto cleanup;
    }
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        goto cleanup;
    }
    if (!X509_set_pubkey(x509, pkey)) {
        goto cleanup;
    }

    // Set the validity period (1 year)
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), 31536000L)) {
        goto cleanup;
    }

    // Sign the certificate with the private key
    BIO_free(bio);
    bio = BIO_new_mem_buf(p_prv_key, private_key_size);
    if (!bio) {
        goto cleanup;
    }
    privkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!privkey) {
        goto cleanup;
    }
    if (!X509_sign(x509, privkey, EVP_sha256())) {
        goto cleanup;
    }

    // Output the certificate in DER format
    BIO_free(bio);
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        goto cleanup;
    }
    if (i2d_X509_bio(bio, x509) <= 0) {
        goto cleanup;
    }

    // Get the pointer to the data in the BIO
    data_len = BIO_get_mem_data(bio, &data_ptr);

    // Allocate memory for the output certificate
    *p_output_cert_size = data_len;
    *pp_output_cert = (uint8_t *)OPENSSL_malloc(*p_output_cert_size);
    if (!*pp_output_cert) {
        goto cleanup;
    }

    // Copy the data to the output certificate
    memcpy(*pp_output_cert, data_ptr, *p_output_cert_size);

    // Success
    result = SGX_SUCCESS;
    ret = 0;

cleanup:
    if (ret != 0 && pp_output_cert && *pp_output_cert) {
        OPENSSL_free(*pp_output_cert);
        *pp_output_cert = NULL;
    }
    if (bio) {
        BIO_free(bio);
    }
    if (x509) {
        X509_free(x509);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (privkey) {
        EVP_PKEY_free(privkey);
    }
    if (name) {
        X509_NAME_free(name);
    }
    ERR_free_strings();
    EVP_cleanup();
    return result;
}


sgx_status_t generate_certificate_and_pkey(X509*& certificate, EVP_PKEY*& pkey)
{
    sgx_status_t qresult = SGX_SUCCESS;
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    uint8_t* output_certificate = NULL;
    size_t output_certificate_size = 0;
    uint8_t* private_key_buffer = nullptr;
    size_t private_key_buffer_size = 0;
    uint8_t* public_key_buffer = nullptr;
    size_t public_key_buffer_size = 0;
    const unsigned char* certificate_buffer_ptr = nullptr;
    BIO* mem = nullptr;
    int key_type = EC_TYPE;

    //if (key_type) {
        
        //PRINT(" generating keys by EC P-384\n");
    //}
    //else
    //{
    //    PRINT(" generating keys by RSA 3072\n");
    //}
    result = generate_key_pair(
        key_type, &public_key_buffer,
        &public_key_buffer_size,
        &private_key_buffer,
        &private_key_buffer_size);
    if (result != SGX_SUCCESS)
    {
        PRINT(" failed to generate RSA key pair\n");
        goto done;
    }

    //PRINT("public_key_buf_size:[%ld]\n", public_key_buffer_size);
    //PRINT("%s\n", public_key_buffer);
    //PRINT("private_key_buf_size:[%ld]\n", private_key_buffer_size);
    //PRINT("%s\n", private_key_buffer);
    qresult = tee_get_self_signed_certificate(//tee_get_certificate_with_evidence
        certificate_subject_name,
        private_key_buffer,
        private_key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        &output_certificate,
        &output_certificate_size);

    if (qresult != SGX_SUCCESS || output_certificate == nullptr)
    {
        if (output_certificate == nullptr)
            PRINT(" null certificate\n");
        p_sgx_tls_qe_err_msg(qresult);
        goto done;
    }

    // temporary buffer required as if d2i_x509 call is successful
    // certificate_buffer_ptr is incremented to the byte following the parsed
    // data. sending certificate_buffer_ptr as argument will keep
    // output_certificate pointer undisturbed.

    certificate_buffer_ptr = output_certificate;

    if ((certificate = d2i_X509(
             nullptr,
             &certificate_buffer_ptr,
             (long)output_certificate_size)) == nullptr)
    {
        PRINT("Failed to convert DER format certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buffer, -1);
    if (!mem)
    {
        PRINT("Failed to convert private key buf into BIO_mem\n");
        goto done;
    }
    if ((pkey = PEM_read_bio_PrivateKey(mem, nullptr, 0, nullptr)) == nullptr)
    {
        PRINT("Failed to convert private key buffer into EVP_KEY format\n");
        goto done;
    }

    result = SGX_SUCCESS;
done:
    if (private_key_buffer)
        free(private_key_buffer);
    if (public_key_buffer)
        free(public_key_buffer);
    certificate_buffer_ptr = nullptr;

    if (mem)
        BIO_free(mem);
    if (output_certificate)
        tee_free_certificate_mock(output_certificate);//tee_free_certificate(output_certificate);
    return result;
}

sgx_status_t load_tls_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& certificate,
    EVP_PKEY*& pkey)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;

    if (generate_certificate_and_pkey(certificate, pkey) != SGX_SUCCESS)
    {
        PRINT("Cannot generate certificate and pkey\n");
        goto exit;
    }

    if (certificate == nullptr)
    {
        PRINT("null cert\n");
        goto exit;
    }

    if (!SSL_CTX_use_certificate(ctx, certificate))
    {
        PRINT("Cannot load certificate on the server\n");
        goto exit;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, pkey))
    {
        PRINT("Cannot load private key on the server\n");
        goto exit;
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        PRINT("Private key does not match the public certificate\n");
        goto exit;
    }
    result = SGX_SUCCESS;
exit:
    return result;
}

sgx_status_t initalize_ssl_context(SSL_CONF_CTX*& ssl_conf_ctx, SSL_CTX*& ctx)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // Configure the SSL context based on Open Enclave's security guidance.
    const char* cipher_list_tlsv12_below =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-"
        "AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-"
        "AES256-SHA384:"
        "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384";
    const char* cipher_list_tlsv13 =
        "TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
    const char* supported_curves = "P-521:P-384:P-256";

    SSL_CONF_CTX_set_ssl_ctx(ssl_conf_ctx, ctx);
    SSL_CONF_CTX_set_flags(
        ssl_conf_ctx,
        SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CLIENT);
    int ssl_conf_return_value = -1;
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MinProtocol", "TLSv1.2")) < 0)
    {
        PRINT(
            "Setting MinProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MaxProtocol", "TLSv1.3")) < 0)
    {
        PRINT(
            "Setting MaxProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "CipherString", cipher_list_tlsv12_below)) < 0)
    {
        PRINT(
            "Setting CipherString for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "Ciphersuites", cipher_list_tlsv13)) < 0)
    {
        PRINT(
            "Setting Ciphersuites for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "Curves", supported_curves)) < 0)
    {
        PRINT(
            "Setting Curves for ssl context configuration failed with error %d "
            "\n",
            ssl_conf_return_value);
        goto exit;
    }
    if (!SSL_CONF_CTX_finish(ssl_conf_ctx))
    {
        PRINT("Error finishing ssl context configuration \n");
        goto exit;
    }
    ret = SGX_SUCCESS;
exit:
    return ret;
}

int read_from_session_peer(
    SSL*& ssl_session)
{
    int ret = -1;
    unsigned char buffer[200]; // the expected payload to be read from peer is
                               // at maximum of size 200
    int bytes_read = 0;
    uint64_t tsc;
    do
    {
        unsigned int len = sizeof(buffer) - 1;
        memset(buffer, 0, sizeof(buffer));
        bytes_read = SSL_read(ssl_session, buffer, (size_t)len);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            PRINT("Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        PRINT(" %d bytes read from session peer\n", bytes_read);
        
        if ((strncmp((const char*)buffer, "GET / HTTP/1.0", 14) == 0) && 
        ((bytes_read == CLIENT_PAYLOAD_SIZE) || (memcmp(CLIENT_PAYLOAD, buffer, bytes_read) == 0))){
            PRINT(" received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }       
        else if ((strncmp((const char*)buffer, "GET /timestamps", 15) == 0) && 
        ((bytes_read == TIMESTAMPS_PAYLOAD_SIZE) || (memcmp(GET_TIMESTAMPS, buffer, bytes_read) == 0))){
            PRINT("demande de ts \n");
            ret = 10;
            goto exit;
        }
  
        else
        {
            PRINT ("Requête non reconnue\n");
            goto exit;
        }
        
    } while (1);

exit:
    return ret;
}


int extract_number(const char *buffer) {
    const char *start_tag = "<p>";
    const char *end_tag = "</p>";
    char *start = strstr(buffer, start_tag);
    if (!start) {
        return -1; 
    }
    start += strlen(start_tag);
    char *end = strstr(start, end_tag);
    if (!end) {
        return -1; 
    }
    char number_str[20];
    strncpy(number_str, start, end - start);
    number_str[end - start] = '\0';
    return atoi(number_str);
}


int read_from_session_peer_tsc(
    SSL*& ssl_session, int& count)
{
    int ret = -1;
    unsigned char buffer[200]; // the expected payload to be read from peer is
                               // at maximum of size 200
    int bytes_read = 0;
    uint64_t tsc;
    do
    {
        unsigned int len = sizeof(buffer) - 1;
        memset(buffer, 0, sizeof(buffer));
        bytes_read = SSL_read(ssl_session, buffer, (size_t)len);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            PRINT("Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        //PRINT(" %d bytes read from session peer\n", bytes_read);
        //PRINT("TIMESTAMPS ASK SIZE : %d\n", TIMESTAMPS_ASK_SIZE);
        //PRINT("Message read : %s\n", buffer);
        // check to see if received payload is expected

        
        if ((strncmp((const char*)buffer, "GET / HTTP/1.0", 14) == 0) && 
        ((bytes_read == CLIENT_PAYLOAD_SIZE) || (memcmp(CLIENT_PAYLOAD, buffer, bytes_read) == 0))){
            PRINT(" received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }       
        else if ((strncmp((const char*)buffer, "GET /timestamps", 15) == 0)){//} &&
        //((bytes_read == TIMESTAMPS_ASK_SIZE-1) || (memcmp(TIMESTAMPS_ASK, buffer, bytes_read+1) == 0))){
            count = extract_number((const char*)buffer);
            //PRINT("count dans read_from_session_peer : %d\n", count);
            //PRINT("demande de ts \n");
            ret = 10;
            goto exit;
        }
  
        else
        {
            PRINT ("Requête non reconnue\n");
            goto exit;
        }
        
    } while (1);

exit:
    return ret;
}


int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int bytes_written = 0;
    int ret = 0;

    while ((bytes_written = SSL_write(ssl_session, payload, payload_length)) <=
           0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        PRINT("Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }

    //PRINT("%lu bytes written to session peer\n\n", payload_length);
exit:
    return ret;
}

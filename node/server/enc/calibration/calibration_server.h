#ifndef CALIBRATION_SERVER_H
#define CALIBRATION_SERVER_H

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../../common/openssl_utility.h"
#include <sgx_trts_exception.h>
#include "sgx_urts.h"
#include "sgx_trts.h"
#include <cstdlib>
#include "sgx_tseal.h"
#include "tls_server_t.h"
#include <sgx_trts_aex.h>
#include <sgx_trts_exception.h>
#include <atomic>
#include <future>
#include "../ssl/ssl_common.h"
#include "../../common/parsing/parsing.h"
#include "../ssl/ssl_server.h"

void ecall_consumer(void);
void calibration(void);

#endif // CALIBRATION_SERVER_H
#include <sgx_quote.h>
#include <sgx_ql_quote.h>
#include <string.h>
#include "sgx_ql_lib_common.h"
#include "sgx_qve_header.h"

void sgx_tls_get_qe_target_info_ocall(sgx_target_info_t* target_info) {
    if (target_info) {
        memset(target_info, 0, sizeof(sgx_target_info_t));
    }
}

void sgx_tls_get_quote_size_ocall(uint32_t* quote_size) {
    if (quote_size) {
        *quote_size = 0;
    }
}

void sgx_tls_get_quote_ocall(const sgx_report_t* report, uint32_t quote_size, uint8_t* quote) {
    // Implementation factice
}

void sgx_tls_get_supplemental_data_size_ocall(uint32_t* supplemental_data_size) {
    if (supplemental_data_size) {
        *supplemental_data_size = 0;
    }
}

void sgx_tls_verify_quote_ocall(const uint8_t* quote, uint32_t quote_size, tee_qv_result_t* qv_result) {
    if (qv_result) {
        *qv_result = SGX_QL_QV_RESULT_OK;
    }
}


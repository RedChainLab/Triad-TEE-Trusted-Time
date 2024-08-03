#include "calibration_server.h"


uint64_t server_time = 0;
uint64_t drift_rate = 0;
uint64_t add_opp_in_2ms = 0;
uint64_t rectify = 0;

static cond_buffer_t buffer = {0, 0, 0,SGX_THREAD_COND_INITIALIZER,SGX_THREAD_COND_INITIALIZER, SGX_THREAD_MUTEX_INITIALIZER};

void ecall_consumer(void){
    cond_buffer_t *b = &buffer;
    sgx_thread_mutex_lock(&b->mutex);
    t_print("calibration start : %d\n", b->calibrationStart);
    while (!b->calibrationStart) {
        sgx_thread_cond_wait(&b->startCalibration, &b->mutex);
    }
    sgx_thread_mutex_unlock(&b->mutex);
    while(b->calibrationStart == 1){
        while(b->isCounting == 1){
            b->count++;
        } 
    }
}

void calibration(){
    int n = 10;
    t_print("--- Starting Calibration ---\n");
    uint32_t count = 0;
    uint64_t mean_tsc_0 = 0;
    uint64_t mean_tsc_500 = 0;
    uint64_t waiting_time = 100;

    cond_buffer_t *b = &buffer;
    sgx_thread_mutex_lock(&b->mutex);
    b->isCounting = 0;
    b->calibrationStart = 1;
    sgx_thread_cond_signal(&b->startCalibration);
    sgx_thread_mutex_unlock(&b->mutex);
    for(int i = 0; i <= n; i++){
        t_print("\n\n");
        launch_tls_client_with_trusted_server("localhost", "12345", i, count, mean_tsc_0, mean_tsc_500, &buffer, waiting_time);
    }
    sgx_thread_mutex_lock(&b->mutex);
    b->calibrationStart = 0;
    sgx_thread_mutex_unlock(&b->mutex);

    mean_tsc_0 /= (int)(n/2+1);
    mean_tsc_500 /= (int)(n/2+1);
    count /= (int)(n/2+1);
    drift_rate = (mean_tsc_500-mean_tsc_0)/(waiting_time*1000);
    add_opp_in_2ms = 2*count/(waiting_time);

    t_print("mean_tsc_0 : %ld\n mean_tsc_500 : %ld\n add_pp_in_2ms : %ld\n drift_rate : %ld\n", mean_tsc_0, mean_tsc_500, add_opp_in_2ms, drift_rate);
    
    //establishing TLS connection with other nodes
    //set_up_tls_server(server_global_eid, &retval, (const char *) "12340", 0);

}


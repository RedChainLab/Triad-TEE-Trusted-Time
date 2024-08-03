#include "tls_server_u.h"
#include <errno.h>

typedef struct ms_set_up_tls_server_t {
	int ms_retval;
	char* ms_port;
	size_t ms_port_len;
	int ms_keep_server_up;
} ms_set_up_tls_server_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_socket_t {
	int ms_retval;
	int ocall_errno;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_u_socket_t;

typedef struct ms_u_bind_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	const struct sockaddr* ms_addr;
	socklen_t ms_len;
} ms_u_bind_t;

typedef struct ms_u_listen_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_n;
} ms_u_listen_t;

typedef struct ms_u_accept_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_accept_t;

typedef struct ms_u_connect_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	const struct sockaddr* ms_addr;
	socklen_t ms_len;
} ms_u_connect_t;

typedef struct ms_u_send_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_n;
	int ms_flags;
} ms_u_send_t;

typedef struct ms_u_recv_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_n;
	int ms_flags;
} ms_u_recv_t;

typedef struct ms_u_setsockopt_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_level;
	int ms_optname;
	const void* ms_optval;
	socklen_t ms_optlen;
} ms_u_setsockopt_t;

typedef struct ms_u_close_t {
	int ms_retval;
	int ms_fd;
} ms_u_close_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_get_current_time_t {
	uint64_t* ms_p_current_time;
} ms_ocall_get_current_time_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_u_sgxssl_write_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_n;
} ms_u_sgxssl_write_t;

typedef struct ms_u_sgxssl_read_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_sgxssl_read_t;

typedef struct ms_u_sgxssl_close_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
} ms_u_sgxssl_close_t;

typedef struct ms_u_sgxssl_open_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_fname;
	int ms_flags;
} ms_u_sgxssl_open_t;

typedef struct ms_sgx_tls_get_qe_target_info_ocall_t {
	quote3_error_t ms_retval;
	sgx_target_info_t* ms_p_target_info;
	size_t ms_target_info_size;
} ms_sgx_tls_get_qe_target_info_ocall_t;

typedef struct ms_sgx_tls_get_quote_size_ocall_t {
	quote3_error_t ms_retval;
	uint32_t* ms_p_quote_size;
} ms_sgx_tls_get_quote_size_ocall_t;

typedef struct ms_sgx_tls_get_quote_ocall_t {
	quote3_error_t ms_retval;
	sgx_report_t* ms_p_report;
	size_t ms_report_size;
	uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
} ms_sgx_tls_get_quote_ocall_t;

typedef struct ms_sgx_tls_get_supplemental_data_size_ocall_t {
	quote3_error_t ms_retval;
	uint32_t* ms_p_supplemental_data_size;
} ms_sgx_tls_get_supplemental_data_size_ocall_t;

typedef struct ms_sgx_tls_verify_quote_ocall_t {
	quote3_error_t ms_retval;
	const uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	time_t ms_expiration_check_date;
	sgx_ql_qv_result_t* ms_p_quote_verification_result;
	sgx_ql_qe_report_info_t* ms_p_qve_report_info;
	size_t ms_qve_report_info_size;
	uint8_t* ms_p_supplemental_data;
	uint32_t ms_supplemental_data_size;
} ms_sgx_tls_verify_quote_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL tls_server_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_socket(void* pms)
{
	ms_u_socket_t* ms = SGX_CAST(ms_u_socket_t*, pms);
	ms->ms_retval = u_socket(ms->ms_domain, ms->ms_type, ms->ms_protocol);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_bind(void* pms)
{
	ms_u_bind_t* ms = SGX_CAST(ms_u_bind_t*, pms);
	ms->ms_retval = u_bind(ms->ms_fd, ms->ms_addr, ms->ms_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_listen(void* pms)
{
	ms_u_listen_t* ms = SGX_CAST(ms_u_listen_t*, pms);
	ms->ms_retval = u_listen(ms->ms_fd, ms->ms_n);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_accept(void* pms)
{
	ms_u_accept_t* ms = SGX_CAST(ms_u_accept_t*, pms);
	ms->ms_retval = u_accept(ms->ms_fd, ms->ms_addr, ms->ms_addrlen_in, ms->ms_addrlen_out);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_connect(void* pms)
{
	ms_u_connect_t* ms = SGX_CAST(ms_u_connect_t*, pms);
	ms->ms_retval = u_connect(ms->ms_fd, ms->ms_addr, ms->ms_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_send(void* pms)
{
	ms_u_send_t* ms = SGX_CAST(ms_u_send_t*, pms);
	ms->ms_retval = u_send(ms->ms_fd, ms->ms_buf, ms->ms_n, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_recv(void* pms)
{
	ms_u_recv_t* ms = SGX_CAST(ms_u_recv_t*, pms);
	ms->ms_retval = u_recv(ms->ms_fd, ms->ms_buf, ms->ms_n, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_setsockopt(void* pms)
{
	ms_u_setsockopt_t* ms = SGX_CAST(ms_u_setsockopt_t*, pms);
	ms->ms_retval = u_setsockopt(ms->ms_fd, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_close(void* pms)
{
	ms_u_close_t* ms = SGX_CAST(ms_u_close_t*, pms);
	ms->ms_retval = u_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_ocall_get_current_time(void* pms)
{
	ms_ocall_get_current_time_t* ms = SGX_CAST(ms_ocall_get_current_time_t*, pms);
	ocall_get_current_time(ms->ms_p_current_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_sgxssl_write(void* pms)
{
	ms_u_sgxssl_write_t* ms = SGX_CAST(ms_u_sgxssl_write_t*, pms);
	ms->ms_retval = u_sgxssl_write(ms->ms_fd, ms->ms_buf, ms->ms_n);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_sgxssl_read(void* pms)
{
	ms_u_sgxssl_read_t* ms = SGX_CAST(ms_u_sgxssl_read_t*, pms);
	ms->ms_retval = u_sgxssl_read(ms->ms_fd, ms->ms_buf, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_sgxssl_close(void* pms)
{
	ms_u_sgxssl_close_t* ms = SGX_CAST(ms_u_sgxssl_close_t*, pms);
	ms->ms_retval = u_sgxssl_close(ms->ms_fd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_u_sgxssl_open(void* pms)
{
	ms_u_sgxssl_open_t* ms = SGX_CAST(ms_u_sgxssl_open_t*, pms);
	ms->ms_retval = u_sgxssl_open(ms->ms_fname, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_tls_get_qe_target_info_ocall(void* pms)
{
	ms_sgx_tls_get_qe_target_info_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_qe_target_info_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_qe_target_info_ocall(ms->ms_p_target_info, ms->ms_target_info_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_tls_get_quote_size_ocall(void* pms)
{
	ms_sgx_tls_get_quote_size_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_quote_size_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_quote_size_ocall(ms->ms_p_quote_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_tls_get_quote_ocall(void* pms)
{
	ms_sgx_tls_get_quote_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_quote_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_quote_ocall(ms->ms_p_report, ms->ms_report_size, ms->ms_p_quote, ms->ms_quote_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_tls_get_supplemental_data_size_ocall(void* pms)
{
	ms_sgx_tls_get_supplemental_data_size_ocall_t* ms = SGX_CAST(ms_sgx_tls_get_supplemental_data_size_ocall_t*, pms);
	ms->ms_retval = sgx_tls_get_supplemental_data_size_ocall(ms->ms_p_supplemental_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_sgx_tls_verify_quote_ocall(void* pms)
{
	ms_sgx_tls_verify_quote_ocall_t* ms = SGX_CAST(ms_sgx_tls_verify_quote_ocall_t*, pms);
	ms->ms_retval = sgx_tls_verify_quote_ocall(ms->ms_p_quote, ms->ms_quote_size, ms->ms_expiration_check_date, ms->ms_p_quote_verification_result, ms->ms_p_qve_report_info, ms->ms_qve_report_info_size, ms->ms_p_supplemental_data, ms->ms_supplemental_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_server_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[30];
} ocall_table_tls_server = {
	30,
	{
		(void*)tls_server_sgx_oc_cpuidex,
		(void*)tls_server_sgx_thread_wait_untrusted_event_ocall,
		(void*)tls_server_sgx_thread_set_untrusted_event_ocall,
		(void*)tls_server_sgx_thread_setwait_untrusted_events_ocall,
		(void*)tls_server_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)tls_server_u_socket,
		(void*)tls_server_u_bind,
		(void*)tls_server_u_listen,
		(void*)tls_server_u_accept,
		(void*)tls_server_u_connect,
		(void*)tls_server_u_send,
		(void*)tls_server_u_recv,
		(void*)tls_server_u_setsockopt,
		(void*)tls_server_u_close,
		(void*)tls_server_ocall_print_string,
		(void*)tls_server_ocall_close,
		(void*)tls_server_ocall_get_current_time,
		(void*)tls_server_u_sgxssl_ftime,
		(void*)tls_server_u_sgxssl_write,
		(void*)tls_server_u_sgxssl_read,
		(void*)tls_server_u_sgxssl_close,
		(void*)tls_server_u_sgxssl_open,
		(void*)tls_server_sgx_tls_get_qe_target_info_ocall,
		(void*)tls_server_sgx_tls_get_quote_size_ocall,
		(void*)tls_server_sgx_tls_get_quote_ocall,
		(void*)tls_server_sgx_tls_get_supplemental_data_size_ocall,
		(void*)tls_server_sgx_tls_verify_quote_ocall,
		(void*)tls_server_pthread_wait_timeout_ocall,
		(void*)tls_server_pthread_create_ocall,
		(void*)tls_server_pthread_wakeup_ocall,
	}
};
sgx_status_t set_up_tls_server(sgx_enclave_id_t eid, int* retval, char* port, int keep_server_up)
{
	sgx_status_t status;
	ms_set_up_tls_server_t ms;
	ms.ms_port = port;
	ms.ms_port_len = port ? strlen(port) + 1 : 0;
	ms.ms_keep_server_up = keep_server_up;
	status = sgx_ecall(eid, 0, &ocall_table_tls_server, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


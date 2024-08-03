#include "tls_server_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_set_up_tls_server(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_set_up_tls_server_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_set_up_tls_server_t* ms = SGX_CAST(ms_set_up_tls_server_t*, pms);
	ms_set_up_tls_server_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_set_up_tls_server_t), ms, sizeof(ms_set_up_tls_server_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_port = __in_ms.ms_port;
	size_t _len_port = __in_ms.ms_port_len ;
	char* _in_port = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_port, _len_port);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_port != NULL && _len_port != 0) {
		_in_port = (char*)malloc(_len_port);
		if (_in_port == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_port, _len_port, _tmp_port, _len_port)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_port[_len_port - 1] = '\0';
		if (_len_port != strlen(_in_port) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = set_up_tls_server(_in_port, __in_ms.ms_keep_server_up);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_port) free(_in_port);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_set_up_tls_server, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[30][1];
} g_dyn_entry_table = {
	30,
	{
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
	}
};


sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_socket(int* retval, int domain, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_socket_t));
	ocalloc_size -= sizeof(ms_u_socket_t);

	if (memcpy_verw_s(&ms->ms_domain, sizeof(ms->ms_domain), &domain, sizeof(domain))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_type, sizeof(ms->ms_type), &type, sizeof(type))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_protocol, sizeof(ms->ms_protocol), &protocol, sizeof(protocol))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_bind(int* retval, int fd, const struct sockaddr* addr, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = len;

	ms_u_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_bind_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_bind_t));
	ocalloc_size -= sizeof(ms_u_bind_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_listen(int* retval, int fd, int n)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_listen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_listen_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_listen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_listen_t));
	ocalloc_size -= sizeof(ms_u_listen_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_accept(int* retval, int fd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_accept_t);
	void *__tmp = NULL;

	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_accept_t));
	ocalloc_size -= sizeof(ms_u_accept_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		memset_verw(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_connect(int* retval, int fd, const struct sockaddr* addr, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = len;

	ms_u_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_connect_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_connect_t));
	ocalloc_size -= sizeof(ms_u_connect_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_send(ssize_t* retval, int fd, const void* buf, size_t n, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_u_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_send_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_send_t));
	ocalloc_size -= sizeof(ms_u_send_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_recv(ssize_t* retval, int fd, void* buf, size_t n, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_u_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_recv_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_recv_t));
	ocalloc_size -= sizeof(ms_u_recv_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_setsockopt(int* retval, int fd, int level, int optname, const void* optval, socklen_t optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optlen;

	ms_u_setsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_setsockopt_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(optval, _len_optval);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optval != NULL) ? _len_optval : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_setsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_setsockopt_t));
	ocalloc_size -= sizeof(ms_u_setsockopt_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_level, sizeof(ms->ms_level), &level, sizeof(level))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_optname, sizeof(ms->ms_optname), &optname, sizeof(optname))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (optval != NULL) {
		if (memcpy_verw_s(&ms->ms_optval, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, optval, _len_optval)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}

	if (memcpy_verw_s(&ms->ms_optlen, sizeof(ms->ms_optlen), &optlen, sizeof(optlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_close_t));
	ocalloc_size -= sizeof(ms_u_close_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));
	ocalloc_size -= sizeof(ms_ocall_close_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_current_time(uint64_t* p_current_time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_current_time = sizeof(uint64_t);

	ms_ocall_get_current_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_current_time_t);
	void *__tmp = NULL;

	void *__tmp_p_current_time = NULL;

	CHECK_ENCLAVE_POINTER(p_current_time, _len_p_current_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_current_time != NULL) ? _len_p_current_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_current_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_current_time_t));
	ocalloc_size -= sizeof(ms_ocall_get_current_time_t);

	if (p_current_time != NULL) {
		if (memcpy_verw_s(&ms->ms_p_current_time, sizeof(uint64_t*), &__tmp, sizeof(uint64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_current_time = __tmp;
		if (_len_p_current_time % sizeof(*p_current_time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_p_current_time, 0, _len_p_current_time);
		__tmp = (void *)((size_t)__tmp + _len_p_current_time);
		ocalloc_size -= _len_p_current_time;
	} else {
		ms->ms_p_current_time = NULL;
	}

	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (p_current_time) {
			if (memcpy_s((void*)p_current_time, _len_p_current_time, __tmp_p_current_time, _len_p_current_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		if (memcpy_verw_s(&ms->ms_timeptr, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_timeptr = __tmp;
		memset_verw(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_timeb_len, sizeof(ms->ms_timeb_len), &timeb_len, sizeof(timeb_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_write(ssize_t* retval, int fd, const void* buf, size_t n)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_u_sgxssl_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_write_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_write_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_write_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_read(ssize_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_sgxssl_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_read_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_read_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxssl_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_close_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_close_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_open(int* retval, const char* fname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxssl_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_open_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_open_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_open_t);

	if (memcpy_verw_s(&ms->ms_fname, sizeof(ms->ms_fname), &fname, sizeof(fname))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_qe_target_info_ocall(quote3_error_t* retval, sgx_target_info_t* p_target_info, size_t target_info_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_target_info = target_info_size;

	ms_sgx_tls_get_qe_target_info_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_qe_target_info_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_target_info = NULL;

	CHECK_ENCLAVE_POINTER(p_target_info, _len_p_target_info);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_target_info != NULL) ? _len_p_target_info : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_qe_target_info_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_qe_target_info_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_qe_target_info_ocall_t);

	if (p_target_info != NULL) {
		if (memcpy_verw_s(&ms->ms_p_target_info, sizeof(sgx_target_info_t*), &__tmp, sizeof(sgx_target_info_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_target_info = __tmp;
		memset_verw(__tmp_p_target_info, 0, _len_p_target_info);
		__tmp = (void *)((size_t)__tmp + _len_p_target_info);
		ocalloc_size -= _len_p_target_info;
	} else {
		ms->ms_p_target_info = NULL;
	}

	if (memcpy_verw_s(&ms->ms_target_info_size, sizeof(ms->ms_target_info_size), &target_info_size, sizeof(target_info_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_target_info) {
			if (memcpy_s((void*)p_target_info, _len_p_target_info, __tmp_p_target_info, _len_p_target_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_quote_size_ocall(quote3_error_t* retval, uint32_t* p_quote_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_quote_size = sizeof(uint32_t);

	ms_sgx_tls_get_quote_size_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_quote_size_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_quote_size = NULL;

	CHECK_ENCLAVE_POINTER(p_quote_size, _len_p_quote_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote_size != NULL) ? _len_p_quote_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_quote_size_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_quote_size_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_quote_size_ocall_t);

	if (p_quote_size != NULL) {
		if (memcpy_verw_s(&ms->ms_p_quote_size, sizeof(uint32_t*), &__tmp, sizeof(uint32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_quote_size = __tmp;
		if (_len_p_quote_size % sizeof(*p_quote_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_p_quote_size, 0, _len_p_quote_size);
		__tmp = (void *)((size_t)__tmp + _len_p_quote_size);
		ocalloc_size -= _len_p_quote_size;
	} else {
		ms->ms_p_quote_size = NULL;
	}

	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_quote_size) {
			if (memcpy_s((void*)p_quote_size, _len_p_quote_size, __tmp_p_quote_size, _len_p_quote_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_quote_ocall(quote3_error_t* retval, sgx_report_t* p_report, size_t report_size, uint8_t* p_quote, uint32_t quote_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_report = report_size;
	size_t _len_p_quote = quote_size;

	ms_sgx_tls_get_quote_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_quote_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_quote = NULL;

	CHECK_ENCLAVE_POINTER(p_report, _len_p_report);
	CHECK_ENCLAVE_POINTER(p_quote, _len_p_quote);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_report != NULL) ? _len_p_report : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote != NULL) ? _len_p_quote : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_quote_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_quote_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_quote_ocall_t);

	if (p_report != NULL) {
		if (memcpy_verw_s(&ms->ms_p_report, sizeof(sgx_report_t*), &__tmp, sizeof(sgx_report_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, p_report, _len_p_report)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_report);
		ocalloc_size -= _len_p_report;
	} else {
		ms->ms_p_report = NULL;
	}

	if (memcpy_verw_s(&ms->ms_report_size, sizeof(ms->ms_report_size), &report_size, sizeof(report_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (p_quote != NULL) {
		if (memcpy_verw_s(&ms->ms_p_quote, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_quote = __tmp;
		if (_len_p_quote % sizeof(*p_quote) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_p_quote, 0, _len_p_quote);
		__tmp = (void *)((size_t)__tmp + _len_p_quote);
		ocalloc_size -= _len_p_quote;
	} else {
		ms->ms_p_quote = NULL;
	}

	if (memcpy_verw_s(&ms->ms_quote_size, sizeof(ms->ms_quote_size), &quote_size, sizeof(quote_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_quote) {
			if (memcpy_s((void*)p_quote, _len_p_quote, __tmp_p_quote, _len_p_quote)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_get_supplemental_data_size_ocall(quote3_error_t* retval, uint32_t* p_supplemental_data_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_supplemental_data_size = sizeof(uint32_t);

	ms_sgx_tls_get_supplemental_data_size_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_get_supplemental_data_size_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_supplemental_data_size = NULL;

	CHECK_ENCLAVE_POINTER(p_supplemental_data_size, _len_p_supplemental_data_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_supplemental_data_size != NULL) ? _len_p_supplemental_data_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_get_supplemental_data_size_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_get_supplemental_data_size_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_get_supplemental_data_size_ocall_t);

	if (p_supplemental_data_size != NULL) {
		if (memcpy_verw_s(&ms->ms_p_supplemental_data_size, sizeof(uint32_t*), &__tmp, sizeof(uint32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_supplemental_data_size = __tmp;
		if (_len_p_supplemental_data_size % sizeof(*p_supplemental_data_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_p_supplemental_data_size, 0, _len_p_supplemental_data_size);
		__tmp = (void *)((size_t)__tmp + _len_p_supplemental_data_size);
		ocalloc_size -= _len_p_supplemental_data_size;
	} else {
		ms->ms_p_supplemental_data_size = NULL;
	}

	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_supplemental_data_size) {
			if (memcpy_s((void*)p_supplemental_data_size, _len_p_supplemental_data_size, __tmp_p_supplemental_data_size, _len_p_supplemental_data_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_tls_verify_quote_ocall(quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, time_t expiration_check_date, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, size_t qve_report_info_size, uint8_t* p_supplemental_data, uint32_t supplemental_data_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_quote = quote_size;
	size_t _len_p_quote_verification_result = sizeof(sgx_ql_qv_result_t);
	size_t _len_p_qve_report_info = qve_report_info_size;
	size_t _len_p_supplemental_data = supplemental_data_size;

	ms_sgx_tls_verify_quote_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_tls_verify_quote_ocall_t);
	void *__tmp = NULL;

	void *__tmp_p_quote_verification_result = NULL;
	void *__tmp_p_qve_report_info = NULL;
	void *__tmp_p_supplemental_data = NULL;

	CHECK_ENCLAVE_POINTER(p_quote, _len_p_quote);
	CHECK_ENCLAVE_POINTER(p_quote_verification_result, _len_p_quote_verification_result);
	CHECK_ENCLAVE_POINTER(p_qve_report_info, _len_p_qve_report_info);
	CHECK_ENCLAVE_POINTER(p_supplemental_data, _len_p_supplemental_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote != NULL) ? _len_p_quote : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_quote_verification_result != NULL) ? _len_p_quote_verification_result : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_qve_report_info != NULL) ? _len_p_qve_report_info : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_supplemental_data != NULL) ? _len_p_supplemental_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_tls_verify_quote_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_tls_verify_quote_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_tls_verify_quote_ocall_t);

	if (p_quote != NULL) {
		if (memcpy_verw_s(&ms->ms_p_quote, sizeof(const uint8_t*), &__tmp, sizeof(const uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_p_quote % sizeof(*p_quote) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, p_quote, _len_p_quote)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_quote);
		ocalloc_size -= _len_p_quote;
	} else {
		ms->ms_p_quote = NULL;
	}

	if (memcpy_verw_s(&ms->ms_quote_size, sizeof(ms->ms_quote_size), &quote_size, sizeof(quote_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_expiration_check_date, sizeof(ms->ms_expiration_check_date), &expiration_check_date, sizeof(expiration_check_date))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (p_quote_verification_result != NULL) {
		if (memcpy_verw_s(&ms->ms_p_quote_verification_result, sizeof(sgx_ql_qv_result_t*), &__tmp, sizeof(sgx_ql_qv_result_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_quote_verification_result = __tmp;
		memset_verw(__tmp_p_quote_verification_result, 0, _len_p_quote_verification_result);
		__tmp = (void *)((size_t)__tmp + _len_p_quote_verification_result);
		ocalloc_size -= _len_p_quote_verification_result;
	} else {
		ms->ms_p_quote_verification_result = NULL;
	}

	if (p_qve_report_info != NULL) {
		if (memcpy_verw_s(&ms->ms_p_qve_report_info, sizeof(sgx_ql_qe_report_info_t*), &__tmp, sizeof(sgx_ql_qe_report_info_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_qve_report_info = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, p_qve_report_info, _len_p_qve_report_info)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_qve_report_info);
		ocalloc_size -= _len_p_qve_report_info;
	} else {
		ms->ms_p_qve_report_info = NULL;
	}

	if (memcpy_verw_s(&ms->ms_qve_report_info_size, sizeof(ms->ms_qve_report_info_size), &qve_report_info_size, sizeof(qve_report_info_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (p_supplemental_data != NULL) {
		if (memcpy_verw_s(&ms->ms_p_supplemental_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_p_supplemental_data = __tmp;
		if (_len_p_supplemental_data % sizeof(*p_supplemental_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_p_supplemental_data, 0, _len_p_supplemental_data);
		__tmp = (void *)((size_t)__tmp + _len_p_supplemental_data);
		ocalloc_size -= _len_p_supplemental_data;
	} else {
		ms->ms_p_supplemental_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_supplemental_data_size, sizeof(ms->ms_supplemental_data_size), &supplemental_data_size, sizeof(supplemental_data_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_quote_verification_result) {
			if (memcpy_s((void*)p_quote_verification_result, _len_p_quote_verification_result, __tmp_p_quote_verification_result, _len_p_quote_verification_result)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_qve_report_info) {
			if (memcpy_s((void*)p_qve_report_info, _len_p_qve_report_info, __tmp_p_qve_report_info, _len_p_qve_report_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_supplemental_data) {
			if (memcpy_s((void*)p_supplemental_data, _len_p_supplemental_data, __tmp_p_supplemental_data, _len_p_supplemental_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}


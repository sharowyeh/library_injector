#pragma once
#include "../stdafx.h"

namespace injector
{
	DLLEXPORT BOOL enable_debug_privilege(HANDLE proc_handle, TOKEN_PRIVILEGES *prev_tp_ptr);
	DLLEXPORT BOOL disable_debug_privilege(HANDLE proc_handle, TOKEN_PRIVILEGES prev_tp);

	DLLEXPORT BOOL inject_remote_thread(HANDLE proc_handle, LPVOID func_ptr, PBYTE param_ptr, SIZE_T param_size,
		ULONG_PTR mem_begin, ULONG_PTR mem_end, ULONG_PTR mem_align);
	DLLEXPORT BOOL inject_x64_remote_thread(HANDLE proc_handle, LPVOID func_ptr, PBYTE param_ptr, SIZE_T param_size);
	DLLEXPORT BOOL inject_x86_remote_thread(HANDLE proc_handle, LPVOID func_ptr, PBYTE param_ptr, SIZE_T param_size);

	DLLEXPORT BOOL inject_process_handle(HANDLE proc_handle);
	DLLEXPORT BOOL inject_process_id(DWORD proc_id);
}

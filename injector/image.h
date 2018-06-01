#pragma once
#include "../stdafx.h"

namespace injector
{
	DLLEXPORT LPVOID map_file_view(const char *file_path, HANDLE *file_handle_ptr, HANDLE *mapping_handle_ptr);
	DLLEXPORT BOOL unmap_file_view(HANDLE file_handle, HANDLE mapping_handle, LPVOID map_view_ptr);
	DLLEXPORT BOOL get_machine_type(const char *file_path, WORD* machine_type_ptr);

	DLLEXPORT LPVOID get_symbol_address(HANDLE proc_handle, const char *module_name, const char *func_name);

	LPVOID image_rva_to_va(ULONG_PTR rva_ptr, LPVOID map_view_ptr);
	DLLEXPORT HMODULE get_loaded_module(HANDLE proc_handle, const char *file_name);
	DLLEXPORT LPVOID get_func_address(HANDLE proc_handle, const char *module_path, const char *func_name);

	DLLEXPORT LPVOID get_func_address(const char *module_name, const char *func_name);

	DLLEXPORT BOOL get_this_module_path(char path_64[MAX_PATH], char path_32[MAX_PATH]);
}
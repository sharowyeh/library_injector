#include "image.h"
#include "../logger.h"
#include <DbgHelp.h>
#include <string>
#include <Psapi.h>

#pragma comment(lib, "Dbghelp.lib")

namespace injector
{
	LPVOID map_file_view(const char *file_path, HANDLE *file_handle_ptr, HANDLE *mapping_handle_ptr)
	{
		HANDLE file_handle = NULL;
		file_handle = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
		if (file_handle == NULL)
		{
			LOGFILE("CreateFile handle is NULL\n");
			return NULL;
		}
		*file_handle_ptr = file_handle;

		HANDLE mapping_handle = NULL;
		mapping_handle = CreateFileMapping(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
		if (mapping_handle == NULL)
		{
			LOGFILE("CreateFileMapping handle is NULL\n");
			CloseHandle(file_handle);
			return NULL;
		}
		*mapping_handle_ptr = mapping_handle;

		LPVOID map_view_ptr = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
		if (map_view_ptr == NULL)
		{
			LOGFILE("MapViewOfFile map view is NULL\n");
			CloseHandle(mapping_handle);
			CloseHandle(file_handle);
			return NULL;
		}

		return map_view_ptr;
	}

	BOOL unmap_file_view(HANDLE file_handle, HANDLE mapping_handle, LPVOID map_view_ptr)
	{
		BOOL result = UnmapViewOfFile(map_view_ptr);
		CloseHandle(mapping_handle);
		CloseHandle(file_handle);
		return result;
	}

	BOOL get_machine_type(const char *file_path, WORD* machine_type_ptr)
	{
		// Get file machine type represent platform architecture
		*machine_type_ptr = IMAGE_FILE_MACHINE_UNKNOWN;

		HANDLE file_handle = NULL;
		HANDLE mapping_handle = NULL;
		LPVOID map_view_ptr = map_file_view(file_path, &file_handle, &mapping_handle);
		if (map_view_ptr == NULL)
			return FALSE;

		IMAGE_NT_HEADERS *header_ptr = ImageNtHeader(map_view_ptr);
		LOGFILE("ImageHeaders: header_ptr=0x%p machine=0x%x\n", header_ptr, header_ptr->FileHeader.Machine);
		if (header_ptr != NULL)
			*machine_type_ptr = header_ptr->FileHeader.Machine;

		// Unmap file's view after using it
		BOOL result = unmap_file_view(file_handle, mapping_handle, map_view_ptr);
		return TRUE;
	}

	LPVOID get_symbol_address(HANDLE proc_handle, const char *module_name, const char *func_name)
	{
		// The method modified and referenced from MS research project

		SetLastError(0);
		//HMODULE module_handle = GetModuleHandleA(module_name);
		HMODULE module_handle = LoadLibraryExA(module_name, NULL, 0);
		LOGFILE("GetModuleHandle: handle=0x%p name=%s err=%d\n", module_handle, module_name, GetLastError());
		if (module_handle == NULL)
			return NULL;

		API_VERSION av;
		ZeroMemory(&av, sizeof(API_VERSION));
		av.MajorVersion = API_VERSION_NUMBER;
		ImagehlpApiVersionEx(&av);
		LOGFILE("ImagehlpApiVersionEx: major=%d\n", av.MajorVersion);
		if (av.MajorVersion < API_VERSION_NUMBER)
			return NULL;

		BOOL result = SymInitialize(proc_handle, NULL, FALSE);
		LOGFILE("SymInitialize: result=%d proc=0x%p\n", result, proc_handle);
		if (result == FALSE)
			return NULL;
		// Reset options
		DWORD opt = SymGetOptions();
		opt &= ~(SYMOPT_CASE_INSENSITIVE |
			SYMOPT_UNDNAME |
			SYMOPT_DEFERRED_LOADS |
			0);
		opt |= (SYMOPT_DEFERRED_LOADS |
			SYMOPT_EXACT_SYMBOLS |
			SYMOPT_NO_UNQUALIFIED_LOADS |
			SYMOPT_INCLUDE_32BIT_MODULES |
			0);
		SymSetOptions(opt);

		// Get base address of loaded module
		ULONG_PTR base_address = SymLoadModule(proc_handle, NULL, module_name, NULL, (ULONG_PTR)module_handle, 0);
		LOGFILE("SymLoadModule: address=0x%p proc=0x%p %s\n", base_address, proc_handle, module_name);
		if (base_address == 0)
			return NULL;

		// Get module info for loaded module name
		IMAGEHLP_MODULE module_info;
		ZeroMemory(&module_info, sizeof(module_info));
		module_info.SizeOfStruct = sizeof(module_info);
		result = SymGetModuleInfo(proc_handle, (ULONG_PTR)module_handle, &module_info);
		LOGFILE("SymGetModuleInfo: result=%d module=%s size=%d\n", result, module_info.ModuleName, module_info.ImageSize);
		if (result == FALSE)
			return NULL;

		// Combine symbol name of function then get its symbol info
		char symbol_name[512] = "";
		sprintf_s(symbol_name, "%s!%s", module_info.ModuleName, func_name);
		struct CSymInfo : SYMBOL_INFO {
			CHAR szRestOfName[512];
		} symbol_info;
		ZeroMemory(&symbol_info, sizeof(symbol_info));
		symbol_info.SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol_info.MaxNameLen = sizeof(symbol_info.szRestOfName) / sizeof(symbol_info.szRestOfName[0]);
		SetLastError(0);
		result = SymFromName(proc_handle, symbol_name, &symbol_info);
		// It should not uses DWORD64, ULONG64 or other 64bit integer types for x86 complier,
		// use ULONG_PTR or LPVOID instead, detours source code uses PBYTE
		LPVOID sym_address = (LPVOID)symbol_info.Address;
		LOGFILE("SymFromName: result=%d symbol address=0x%p name=%s err=%d\n", result, sym_address, symbol_name, GetLastError());
		if (result == FALSE)
			return NULL;

		return sym_address;
	}

	LPVOID image_rva_to_va(ULONG_PTR rva_ptr, LPVOID map_view_ptr)
	{
		PIMAGE_NT_HEADERS header_ptr = ImageNtHeader(map_view_ptr);
		// Copy section header from nt header
		PIMAGE_SECTION_HEADER section_ptr = IMAGE_FIRST_SECTION(header_ptr);
		IMAGE_SECTION_HEADER sections[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		memcpy(&sections, section_ptr, sizeof(sections[0]) * header_ptr->FileHeader.NumberOfSections);
		for (DWORD n = 0; n < header_ptr->FileHeader.NumberOfSections; n++)
		{
			DWORD start = sections[n].VirtualAddress;
			DWORD end = start + sections[n].SizeOfRawData;
			if (rva_ptr >= start && rva_ptr < end)
			{
				return (PBYTE)map_view_ptr + sections[n].PointerToRawData +
					rva_ptr - sections[n].VirtualAddress;
			}
		}
		return NULL;
	}

	HMODULE get_loaded_module(HANDLE proc_handle, const char *file_path)
	{
		HMODULE modules[1024];
		DWORD needed;
		if (EnumProcessModulesEx(proc_handle, modules, sizeof(modules), &needed, LIST_MODULES_ALL))
		{
			for (size_t i = 0; i < (needed / sizeof(HMODULE)); i++)
			{
				char module_name[MAX_PATH] = "";
				char file_name[MAX_PATH] = "";
				GetModuleFileNameExA(proc_handle, modules[i], module_name, sizeof(module_name));
				std::string module_str(module_name);
				std::string file_str(file_path);
				module_str = module_str.substr(module_str.find_last_of('\\') + 1);
				file_str = file_str.substr(file_str.find_last_of('\\') + 1);
				sprintf_s(module_name, "%s", module_str.c_str());
				sprintf_s(file_name, "%s", file_str.c_str());
				if (_stricmp(module_name, file_name) != 0)
					continue;

				LOGFILE("GetLoadedModule: handle=0x%p name=%s file=%s\n", modules[i], module_name, file_name);
				return modules[i];
			}
		}
		return NULL;
	}

	LPVOID get_func_address(HANDLE proc_handle, const char *file_path, const char *func_name)
	{
		/*setlocale(LC_ALL, "");
		size_t path_len = strlen(file_path) + 1;
		wchar_t wstr[MAX_PATH] = L"";
		mbstowcs_s(&path_len, wstr, file_path, path_len);
		LOGFILE("MbsToWcs: path=%S\n", wstr);

		LPVOID map_view_ptr = get_map_view(wstr);*/
		HANDLE file_handle = NULL;
		HANDLE mapping_handle = NULL;
		LPVOID map_view_ptr = map_file_view(file_path, &file_handle, &mapping_handle);
		LOGFILE("MapView: view_ptr=0x%p file=%s\n", map_view_ptr, file_path);
		if (map_view_ptr == NULL)
			return NULL;

		PIMAGE_NT_HEADERS header_ptr = ImageNtHeader(map_view_ptr);
		LOGFILE("ImageHeaders: header_ptr=0x%p magic=0x%x base=0x%p\n", header_ptr, header_ptr->OptionalHeader.Magic, header_ptr->OptionalHeader.ImageBase);
		if (header_ptr == NULL)
		{
			unmap_file_view(file_handle, mapping_handle, map_view_ptr);
			return NULL;
		}

		// Optional header depends on file's architecture target instead of current dll's compiler target
		// If given file's optional header magic is 0x10b(PE32 for x86) or 0x20b(PE32+ for x64)
		// uses architecture specific data structure for headers_ptr
		PIMAGE_NT_HEADERS32 header_ptr32 = (PIMAGE_NT_HEADERS32)header_ptr;
		PIMAGE_NT_HEADERS64 header_ptr64 = (PIMAGE_NT_HEADERS64)header_ptr;

		ULONG_PTR base_ptr = 0;
		ULONG_PTR export_rva = 0;
		PIMAGE_EXPORT_DIRECTORY export_ptr = NULL;
		if (header_ptr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			base_ptr = (ULONG_PTR)header_ptr32->OptionalHeader.ImageBase;
			export_rva = (ULONG_PTR)
				header_ptr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			//TODO: section offset may x86 x64 specific
			export_ptr = (PIMAGE_EXPORT_DIRECTORY)
				image_rva_to_va(export_rva, map_view_ptr);
		}
		else if (header_ptr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			base_ptr = (ULONG_PTR)header_ptr64->OptionalHeader.ImageBase;
			export_rva = (ULONG_PTR)
				header_ptr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			// RVA to VA
			export_ptr = (PIMAGE_EXPORT_DIRECTORY)
				image_rva_to_va(export_rva, map_view_ptr);
		}
		LOGFILE("ImageExportDir: base=0x%p rva=0x%x ptr=%p\n", base_ptr, export_rva, export_ptr);
		if (export_rva == NULL || export_ptr == 0)
		{
			unmap_file_view(file_handle, mapping_handle, map_view_ptr);
			return NULL;
		}

		LOGFILE("ExportFunc: num=%d\n", export_ptr->NumberOfFunctions);
		ULONG_PTR names_rva = export_ptr->AddressOfNames;
		LPVOID names_ptr = image_rva_to_va(names_rva, map_view_ptr);
		LOGFILE("ExportName: rva=0x%x ptr=0x%p num=%d\n", names_rva, names_ptr, export_ptr->NumberOfNames);
		ULONG_PTR ordinals_rva = export_ptr->AddressOfNameOrdinals;
		LPVOID ordinals_ptr = image_rva_to_va(ordinals_rva, map_view_ptr);
		ULONG_PTR funcs_rva = export_ptr->AddressOfFunctions;
		LPVOID funcs_ptr = image_rva_to_va(funcs_rva, map_view_ptr);
		LPVOID result_ptr = NULL;
		for (size_t i = 0; i < export_ptr->NumberOfNames; i++)
		{
			ULONG_PTR name_rva = ((DWORD *)names_ptr)[i];
			char *name_ptr = (char *)image_rva_to_va(name_rva, map_view_ptr);
			if (_stricmp(name_ptr, func_name) != 0)
				continue;

			WORD ordinal = ((WORD *)ordinals_ptr)[i];
			ULONG_PTR func_rva = ((DWORD *)funcs_ptr)[ordinal];
			ULONG_PTR base_func_ptr = base_ptr + func_rva;
			// following 2 lines are sb code from github not my expect
			//ULONG_PTR func2_rva = export_ptr->AddressOfFunctions + ordinal * 4;
			//LPVOID func2_ptr = detours_rva_to_va(func2_rva, map_view_ptr);
			LOGFILE(" ImageExportName: index=%d name=%s ord=0x%x func=0x%x ptr=0x%p\n", i, name_ptr, ordinal, func_rva, base_func_ptr);//, func2_rva, func2_ptr);
																																	   // The function pointer in virtual address should be module loaded base + func rva.
																																	   // If given proc_handle is NULL, return RVA or plus image base_ptr?
																																	   // If given proc_handle exists, get module handle as its base address from proc_handle.
			if (proc_handle == NULL)
			{
				result_ptr = (LPVOID)func_rva;
				break;
			}

			// Get loaded module base address from remote process
			HMODULE module_handle = get_loaded_module(proc_handle, file_path);
			if (module_handle == NULL)
			{
				result_ptr = (LPVOID)func_rva;
				break;
			}

			ULONG_PTR loaded_func_ptr = (ULONG_PTR)module_handle + func_rva;
			LOGFILE("LoadedModuleFunc: ptr=0x%p\n", loaded_func_ptr);
			result_ptr = (LPVOID)loaded_func_ptr;
			break;
		}
		// Unmap file's view after using it
		unmap_file_view(file_handle, mapping_handle, map_view_ptr);
		return result_ptr;
	}

	LPVOID get_func_address(const char *module_name, const char *func_name)
	{
		//HMODULE module_handle = GetModuleHandleA(module_name);
		HMODULE module_handle = LoadLibraryExA(module_name, NULL, 0);
		if (module_handle == NULL)
			return NULL;

		// Try GetProcAddress
		LPVOID address = (LPVOID)GetProcAddress(module_handle, func_name);
		LOGFILE("GetProcAddress: %s!%s=0x%p module_base=0x%p\n", module_name, func_name, address, module_handle);
		if (address != NULL)
			return address;

		return NULL;
	}

	BOOL get_this_module_path(char path_64[MAX_PATH], char path_32[MAX_PATH])
	{
		HMODULE this_module = NULL;
		BOOL result = GetModuleHandleExA(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCSTR)&get_this_module_path, &this_module
		);
		//TODO: If result gets failed, it should be assigned from dllmain
		if (result == FALSE)
			this_module = NULL;

		char dll_path[MAX_PATH] = "";
		GetModuleFileNameA(this_module, dll_path, MAX_PATH);
		std::string path = std::string(dll_path);
		// Module file naming
		// x64: name64.dll
		// x86: name.dll
#if _WIN64
		strcpy_s(path_64, strlen(dll_path) + 1, dll_path);

		path = path.substr(0, path.find_last_of(".") - 2);
		sprintf_s(path_32, path.length() + 5, "%s.dll", path.c_str());
#else
		strcpy_s(path_32, strlen(dll_path) + 1, dll_path);

		path = path.substr(0, path.find_last_of("."));
		sprintf_s(path_64, path.length() + 7, "%s64.dll", path.c_str());
#endif
		return TRUE;
	}
}
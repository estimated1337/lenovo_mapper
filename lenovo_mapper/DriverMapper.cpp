#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <conio.h>
#include "DriverMapper.hpp"
#include "loadup.hpp"
#include "LenovoMemoryMgr.h"
#include "ldiagd.hpp"

BOOL DriverMapper::Init()
{
	const auto [result, reg_key] = driver::load(ldiagd_buffer, sizeof(ldiagd_buffer));

	if (NT_SUCCESS(result))
	{
		service_name = reg_key;
		return TRUE;
	}

	return FALSE;
}

BOOL DriverMapper::Shutdown()
{
	auto result = driver::unload(service_name);

	return NT_SUCCESS(result);
}

NTSTATUS DriverMapper::MapDriver(const std::string& driver_path)
{
	const auto image_vec = ReadAllBytes(driver_path.c_str());

	if (!image_vec.size()) return STATUS_UNSUCCESSFUL;

	LenovoMemoryMgr lm = LenovoMemoryMgr();

	BOOL hasInit = lm.Init(service_name);

	if (!hasInit)
	{
		lm.Shutdown();
		return STATUS_UNSUCCESSFUL;
	}

	const auto image_ptr = reinterpret_cast<uintptr_t>(image_vec.data());

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(image_ptr)->e_magic != 0x5A4D)
	{
		std::cout << "invalid file!" << std::endl;

		lm.Shutdown();
		return STATUS_UNSUCCESSFUL;
	}

	const auto image_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(image_ptr +
		reinterpret_cast<IMAGE_DOS_HEADER*>(image_ptr)->e_lfanew);

	const auto image_optional_header = &image_nt_headers->OptionalHeader;
	const auto image_file_header = &image_nt_headers->FileHeader;

	if (image_file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		std::cout << "invalid platform!" << std::endl;

		lm.Shutdown();
		return STATUS_UNSUCCESSFUL;
	}

	const auto aligned_image_size = (image_optional_header->SizeOfImage & ~(0x1000 - 0x1)) + 0x1000;

	const auto mapped_driver_image =
		VirtualAlloc(nullptr, aligned_image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	const auto mapped_driver_image_ptr = reinterpret_cast<uintptr_t>(mapped_driver_image);

	auto mm_allocate_independent_pages = lm.mm_allocate_independent_pages_offset + lm.NtosBase;
	auto mm_set_page_protection = lm.mm_set_page_protection_offset + lm.NtosBase;

	uint32_t node = -1;
	const auto mapped_driver_base = lm.CallKernelFunction(mm_allocate_independent_pages, aligned_image_size, node, 0, 0);
	lm.CallKernelFunction(mm_set_page_protection, mapped_driver_base, aligned_image_size, PAGE_EXECUTE_READWRITE, 0);

	const auto entry_point_address = mapped_driver_base + image_optional_header->AddressOfEntryPoint;

	// copy driver sections

	auto image_section_header = IMAGE_FIRST_SECTION(image_nt_headers);

	for (uint32_t i = 0; i != image_file_header->NumberOfSections; ++i, ++image_section_header)
	{
		if (image_section_header->SizeOfRawData)
		{
			const auto dst = reinterpret_cast<void*>(mapped_driver_image_ptr +
				image_section_header->VirtualAddress);

			const auto src = reinterpret_cast<void*>(image_ptr +
				image_section_header->PointerToRawData);

			memcpy(dst, src, image_section_header->SizeOfRawData);
		}
	}

	// process relocations

	const auto location_delta = mapped_driver_base - image_optional_header->ImageBase;

	if (location_delta)
	{
		if (image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			auto relocation_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				mapped_driver_image_ptr +
				image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while (relocation_data->VirtualAddress)
			{
				uint32_t amount_of_entries = (relocation_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1;
				uint16_t* relative_info = reinterpret_cast<uint16_t*>(relocation_data + 1);

				for (uint32_t i = 0; i != amount_of_entries; ++i, ++relative_info)
				{
					if ((*relative_info >> 0x0C) == IMAGE_REL_BASED_DIR64)
					{
						auto patch_address = reinterpret_cast<uintptr_t*>(mapped_driver_image_ptr
							+ relocation_data->VirtualAddress + ((*relative_info) & 0xFFF));

						*patch_address += location_delta;
					}
				}

				relocation_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
					reinterpret_cast<uint8_t*>(relocation_data) +
					relocation_data->SizeOfBlock);
			}
		}
	}

	// process imports

	if (image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto image_import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			reinterpret_cast<uintptr_t>(mapped_driver_image) +
			image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (image_import_descriptor->Name)
		{
			const auto module_name = reinterpret_cast<char*>(mapped_driver_image_ptr +
				image_import_descriptor->Name);

			uintptr_t* thunk_reference = reinterpret_cast<uintptr_t*>(
				mapped_driver_image_ptr + image_import_descriptor->OriginalFirstThunk);
			uintptr_t* function_reference = reinterpret_cast<uintptr_t*>(
				mapped_driver_image_ptr + image_import_descriptor->FirstThunk);

			if (!thunk_reference) thunk_reference = function_reference;

			for (; *thunk_reference; ++thunk_reference, ++function_reference)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*thunk_reference))
				{
					const auto import_function = lm.GetKernelExport(reinterpret_cast<char*>(*thunk_reference & 0xFFFF));

					if (!import_function)
					{
						std::cout << "cant find import address!" << std::endl;

						VirtualFree(mapped_driver_image, aligned_image_size, MEM_RELEASE);

						lm.Shutdown();
						return STATUS_UNSUCCESSFUL;
					}

					*function_reference = import_function;
				}
				else
				{
					auto image_import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
						mapped_driver_image_ptr + (*thunk_reference));

					const auto import_function = lm.GetKernelExport(image_import_by_name->Name);

					if (!import_function)
					{
						std::cout << "cant find import address!" << std::endl;

						VirtualFree(mapped_driver_image, aligned_image_size, MEM_RELEASE);

						lm.Shutdown();
						return STATUS_UNSUCCESSFUL;
					}

					*function_reference = import_function;
				}
			}

			++image_import_descriptor;
		}
	}

	const auto rtl_copy_memory = lm.GetKernelExport("RtlCopyMemory");

	lm.CallKernelFunction(rtl_copy_memory, mapped_driver_base, reinterpret_cast<UINT64>(mapped_driver_image), aligned_image_size, 0);

	VirtualFree(mapped_driver_image, aligned_image_size, MEM_RELEASE);

	const auto status = lm.CallKernelFunction(entry_point_address, mapped_driver_base, 0x1337, 0, 0);

	lm.Shutdown();

	return status;
}

std::vector<uint8_t> DriverMapper::ReadAllBytes(char const* filename)
{
	std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
	std::ifstream::pos_type pos = ifs.tellg();

	std::vector<uint8_t> result(pos);

	ifs.seekg(0, std::ios::beg);
	ifs.read(reinterpret_cast<char*>(&result[0]), pos);

	return result;
}

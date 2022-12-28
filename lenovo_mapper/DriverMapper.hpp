#pragma once
#include <vector>
#include <fstream>

class DriverMapper
{
public:
	DriverMapper() {};
	~DriverMapper() {};

	BOOL Init();
	BOOL Shutdown();
	
	NTSTATUS MapDriver(const std::string& driver_path);

private:
	std::vector<uint8_t> ReadAllBytes(char const* filename);

	std::string service_name;
};
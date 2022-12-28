#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <conio.h>
#include "DriverMapper.hpp"

int main() 
{
	DriverMapper mapper = DriverMapper();
	
	BOOL hasInit = mapper.Init();
	
	if (hasInit) 
	{
		const auto status = mapper.MapDriver("some_driver.sys");

		std::cout << std::hex << status << std::endl;

		mapper.Shutdown();
	}
	
	return 0;
}

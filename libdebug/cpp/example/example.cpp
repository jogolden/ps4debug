#include "PS4DBG.hpp"
#include <iostream>

int main()
{
	libdebug::PS4DBG ps4("192.168.1.12");
	ps4.Connect();
	auto procList  = ps4.GetProcessList();
	auto proc = procList.FindProcess("eboot.bin");
	ps4.Notify(210, "Hello);
	std::cout << proc->name;
	return 0;
}

#include "PS4DBG.hpp"
#include <iostream>

void Breadsticks(uint32_t lwpid, uint32_t status, const std::string& tdname, libdebug::regs regs, libdebug::fpregs fpregs, libdebug::dbregs dbregs)
{
	std::cout << "lwpid: " << lwpid << std::endl;
	std::cout << "status: " << status << std::endl;
	std::cout << "tdname: " << tdname << std::endl;
	std::cout << "rip: 0x" << std::hex << regs.r_rip << std::endl;
	std::cout << "rax: 0x" << std::hex << regs.r_rax << std::endl;
}
int main()
{
	
	libdebug::PS4DBG ps4("192.168.1.147");
	ps4.Connect();
	auto procList  = ps4.GetProcessList();
	auto proc = procList.FindProcess("eboot.bin");
	if(!proc)
	{
		return 0;
	}
	auto entries = ps4.GetProcessMaps(proc->pid);
	uint64_t executable;
	for(auto entry : entries.entries)
	{
		if (entry->prot == 5)
		{
			std::cout << "executable base : 0x" << std::hex << entry->start << std::endl;
			executable = entry->start;
			break;
		}
	}
	if(!executable)
	{
		return 0;
	}
	auto info = ps4.GetProcessInfo(proc->pid);
	std::cout << info.name << " " << info.titleid << std::endl;
	
	ps4.Notify(210, "Hello");

	ps4.AttachDebugger(proc->pid, Breadsticks);
	ps4.ProcessKill();
	auto info2 = ps4.GetThreadList();
	std::cout << "**Threads**\r\n";
	for(auto thr : info2)
	{
		auto info3 = ps4.GetThreadInfo(thr);
		std::cout << "name: " << info3.name << " pid: " << info3.pid << " priority: " << info3.priority << "\r\n";
	}
	auto regs = ps4.GetRegisters(info2[info2.size() - 1]);
	//std::cout << proc->name;
	while(true)
	{
		
	}
	return 0;
}

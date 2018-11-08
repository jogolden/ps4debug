#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace libdebug
{
	class Process
	{
	public:
		const std::string name;
		const int32_t pid;
		
		Process(const std::string &name, int32_t pid);
	};
	class ProcessList
	{
	public:
		std::vector<Process*> processes;
	
		ProcessList(int32_t number, const std::vector<std::string> &names, const std::vector<int32_t> &pids);
		~ProcessList();
		Process* FindProcess(const std::string &name, bool contains = false);	
	};
	
	struct MemoryEntry
	{
	public:
		std::string name;
		uint64_t start;
		uint64_t end;
		uint64_t offset;
		uint32_t prot;
	};
	
	class ProcessMap
	{
	public:
		const int32_t pid;
		const std::vector<MemoryEntry*> entries;
		
		ProcessMap(int32_t pid, const std::vector<MemoryEntry*> &entries);
		~ProcessMap();
		MemoryEntry* FindEntry(const std::string &name, bool contains = false);
		MemoryEntry* FindEntry(uint64_t size);
	};
	
	struct ProcessInfo
	{
		uint8_t name[40];
		uint8_t path[64];
		uint8_t titleid[16];
		uint8_t contentid[64];
	};
	
	struct ThreadInfo
	{
		int32_t pid;
		int32_t priority;
		uint8_t name[32];
	};
}

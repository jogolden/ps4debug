#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace libdebug
{
	class Process : public std::enable_shared_from_this<Process>
	{
	public:
		const std::string name;
		const int32_t pid;
		
		Process(const std::string &name, int32_t pid);
	};
	
	class ProcessList : public std::enable_shared_from_this<ProcessList>
	{
	public:
		std::vector<std::shared_ptr<Process>> processes;
	
		ProcessList(int32_t number, const std::vector<std::string> &names, const std::vector<int32_t> &pids);
		std::shared_ptr<Process> FindProcess(const std::string &name, bool contains = false);
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
		const std::vector<std::shared_ptr<MemoryEntry>> entries;
		
		ProcessMap(int32_t pid, std::vector<std::shared_ptr<MemoryEntry>> entries);
		
		std::shared_ptr<MemoryEntry> FindEntry(const std::string &name, bool contains = false);
		std::shared_ptr<MemoryEntry> FindEntry(uint64_t size);
	};
	
	struct ProcessInfo
	{
		int32_t pid;
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

#include "Process.hpp"

namespace libdebug
{
    Process::Process(const std::string &name, int32_t pid) : name(name), pid(pid)
    {

    }

    ProcessList::ProcessList(int32_t number, const std::vector<std::string> &names, const std::vector<int32_t> &pids)
    {
		processes = std::vector<Process*>(number);
        for(int32_t i = 0; i < number; i++)
        {
            processes[i] =  new Process(names[i], pids[i]);
        }
        
    }
    
    ProcessList::~ProcessList()
    {
        for(auto process : processes)
        {
            delete process;
        }
    }
    

    Process* ProcessList::FindProcess(const std::string &name, bool contains)
    {
        for(auto process : processes)
        {
            if(contains)
            {
                if(process->name.find(name) != std::string::npos)
                    return process;
            }
            else
            {
                if(process->name == name)
                    return process;
            }
        }
        return nullptr;
    }

	ProcessMap::ProcessMap(int32_t pid, const std::vector<MemoryEntry*> &entries) : pid(pid), entries(entries)
    {

    }

	ProcessMap::~ProcessMap()
    {
		for(auto entry : entries)
		{
			delete entry;
		}
    }

	MemoryEntry* ProcessMap::FindEntry(const std::string &name, bool contains)
    {
        for(auto entry : entries)
        {
            if(contains)
            {
              if(entry->name.find(name) != std::string::npos) 
                return entry;  
            }
            else
            {
                if(entry->name == name)
                    return entry;
            }
        }
        return nullptr;
    }

    MemoryEntry* ProcessMap::FindEntry(uint64_t size)
    {
        for(auto entry : entries)
        {
            if(entry->end - entry->start == size)
                return entry;
        }
        return nullptr;
    }

}
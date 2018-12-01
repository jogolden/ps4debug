#include "PS4DBG.hpp"

namespace libdebug
{
	PS4DBG::PS4DBG(const std::string &ip)
	{
#if defined(PLATFORM_WINDOWS)
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
		sock = socket(AF_INET, SOCK_STREAM, 0);
		server.sin_family = AF_INET;
		server.sin_port = htons(PS4DBG_PORT);
		inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

	}

	PS4DBG::~PS4DBG()
	{
		shutdown(sock, 2);	
		CloseSocket(sock);
	}

	void PS4DBG::Connect()
	{
		int32_t i = 1;
		setsockopt(sock, IPPROTO_TCP, 0x01 /*TCP_NODELAY*/, (char *)&i, sizeof(i));
		i = 10 * 1000;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&i, sizeof(i));

		i = NET_MAX_LENGTH;
		setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&i, sizeof(i));
		setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&i, sizeof(i));
		connect(sock, (sockaddr*)&server, sizeof(server));
		connected = true;
	}

	void PS4DBG::Disconnect()
	{
		shutdown(sock, 2);
		CloseSocket(sock);
		connected = false;
	}

	void PS4DBG::CheckConnected()
	{
		if(!connected)
		{
			throw ("libdbg: not connected");
			
		}
	}
	void PS4DBG::CheckDebugging()
	{
		if(!debugging)
		{
			throw ("libdbg: not debugging");
		}
	}

	bool PS4DBG::IsConnected()
	{
		return connected;
	}

	bool PS4DBG::IsDebugging()
	{
		return debugging;
	}

	std::string PS4DBG::GetLibraryDebugVersion()
	{
		return LIBRARY_VERSION;
	}

	std::string PS4DBG::GetConsoleDebugVersion()
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_VERSION, 0);

		int32_t length;
		recv(sock, (char*)&length, 4, 0);
		std::vector<uint8_t> data(length);
		recv(sock, (char*)data.data(), length, 0);
		std::string ret(data.begin(), data.end());
		return ret;
	}

#pragma  region Network
	void PS4DBG::SendCMDPacket(CMDS cmd, int32_t length, const std::vector<std::any> &fields)
	{
		CMDPacket packet = {CMD_PACKET_MAGIC, (uint32_t)cmd, (uint32_t)length};
		std::vector<uint8_t> data(length);
		int32_t offset = 0;
		for (auto field : fields)
		{
			if (field.type() == typeid(int8_t))
			{
				int8_t temp = std::any_cast<int8_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
			else if (field.type() == typeid(uint8_t))
			{
				uint8_t temp = std::any_cast<uint8_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
			else if (field.type() == typeid(int16_t))
			{
				int16_t temp = std::any_cast<int16_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
			else if (field.type() == typeid(uint16_t))
			{
				uint16_t temp = std::any_cast<uint16_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
			else if (field.type() == typeid(int32_t))
			{
				int32_t temp = std::any_cast<int32_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
			else if (field.type() == typeid(uint32_t))
			{
				uint32_t temp = std::any_cast<uint32_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
			else if (field.type() == typeid(int64_t))
			{
				int64_t temp = std::any_cast<int64_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
			else if (field.type() == typeid(uint64_t))
			{
				uint64_t temp = std::any_cast<uint64_t>(field);
				std::memcpy(&data[offset], &temp, sizeof(temp));
				offset += sizeof(temp);
			}
		}
		send(sock, (char*)&packet, sizeof(packet), 0);
		if(!data.empty())
		{
			SendData(data, length);
		}
	}

	PS4DBG::CMD_STATUS  PS4DBG::ReceiveStatus()
	{
		CMD_STATUS status;
		int32_t rcv = recv(sock, (char*)&status, 4, 0);
		return status;
	}

	PS4DBG::CMD_STATUS  PS4DBG::CheckStatus()
	{
		const CMD_STATUS status = ReceiveStatus();
		if (status != CMD_STATUS::CMD_SUCCESS)
		{

		}
		return status;
	}

	void PS4DBG::SendData(const std::vector<uint8_t> &data, int32_t length)
	{
		int32_t left = length;
		int32_t offset = 0;
		int32_t sent;

		while (left > 0)
		{
			if (left > NET_MAX_LENGTH)
			{
				std::vector<uint8_t> bytes(data.begin() + offset, data.begin() + offset + NET_MAX_LENGTH);
				sent = send(sock, (char*)&bytes[0], NET_MAX_LENGTH, 0);
			}
			else
			{
				std::vector<uint8_t> bytes(data.begin() + offset, data.begin() + offset + left);
				sent = send(sock, (char*)&bytes[0], left, 0);
			}
			offset += sent;
			left -= sent;
		}
	}

	std::vector<uint8_t> PS4DBG::ReceiveData(int32_t length)
	{
		std::vector<uint8_t> data(length);
		int32_t left = length;
		int32_t offset = 0;
		while (left > 0)
		{
			if (left > NET_MAX_LENGTH)
			{
				int32_t rcv = recv(sock, (char*)&data[offset], NET_MAX_LENGTH, 0);
				offset += rcv;
				left -= rcv;
			}
			else
			{
				int32_t rcv = recv(sock, (char*)&data[offset], left, 0);
				offset += rcv;
				left -= rcv;
			}
		}
		return data;
	}
#pragma endregion

#pragma  region Proc
	ProcessList PS4DBG::GetProcessList()
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_PROC_LIST, 0);
		CheckStatus();
		int32_t number = 0;
		recv(sock, (char*)&number, 4, 0);

		std::vector<uint8_t> data = ReceiveData(number * PROC_LIST_ENTRY_SIZE);
		std::vector<std::string> names(number);
		std::vector<int32_t> pids(number);
		std::vector<std::string> titleids(number);

		for (int32_t i = 0; i < number; i++)
		{
			int32_t offset = i * PROC_LIST_ENTRY_SIZE;
			names[i] = std::string((char*)&data[offset]);
			pids[i] = *(int32_t*)(&data[offset + 32]);
		}
		return ProcessList(number, names, pids);
	}

	ProcessMap PS4DBG::GetProcessMaps(int32_t pid)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_PROC_MAPS, CMD_PROC_MAPS_PACKET_SIZE, {pid});
		CheckStatus();

		// recv count
		int32_t number = 0;
		recv(sock, (char*)&number, sizeof(uint32_t), 0);

		// recv data
		std::vector<uint8_t> data = ReceiveData(number * PROC_MAP_ENTRY_SIZE);

		// parse data
		std::vector<std::shared_ptr<MemoryEntry>> entries(number);
		for (int32_t i = 0; i < number; i++)
		{
			int32_t offset = i * PROC_MAP_ENTRY_SIZE;
			entries[i] = std::make_shared<MemoryEntry>();
			entries[i]->name = std::string((char*)&data[offset]);
			entries[i]->start = *(uint64_t*)(&data[offset + 32]);
			entries[i]->end = *(uint64_t*)(&data[offset + 40]);
			entries[i]->offset = *(uint64_t*)(&data[offset + 48]);
			entries[i]->prot = *(uint16_t*)(&data[offset + 56]);
		}

		return ProcessMap(pid, entries);
	}
	
	std::vector<uint8_t> PS4DBG::ReadMemory(int32_t pid, uint64_t address, int32_t length)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_PROC_READ, CMD_PROC_READ_PACKET_SIZE, { pid, address, length });
		CheckStatus();
		return ReceiveData(length);
	}

	void PS4DBG::WriteMemory(int32_t pid, uint64_t address, const std::vector<uint8_t> &data)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_PROC_WRITE, CMD_PROC_WRITE_PACKET_SIZE, { pid, address, data.size()});
		CheckStatus();
		SendData(data, data.size());
		CheckStatus();

	}
	
	uint64_t PS4DBG::InstallRPC(int32_t pid)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_PROC_INTALL, CMD_PROC_INSTALL_PACKET_SIZE, {pid});
		CheckStatus();
		uint64_t data = *(int64_t*)&ReceiveData(PROC_INSTALL_SIZE)[0];
		return data;
	}

	uint64_t PS4DBG::Call(int32_t pid, uint64_t rpcstub, uint64_t address, const std::vector<std::any> &args)
	{
		CheckConnected();

		std::vector<uint8_t> data(CMD_PROC_CALL_PACKET_SIZE);
		std::memcpy(data.data(), &pid, sizeof(pid));
		std::memcpy(data.data() + 4, &rpcstub, sizeof(rpcstub));
		std::memcpy(data.data() + 12, &address, sizeof(address));
		int num = 0;
		int32_t offset = 20;
		for (auto arg : args)
		{
			uint64_t reg = 0;
			if (arg.type() == typeid(int8_t))
			{
				int8_t temp = std::any_cast<int8_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			else if (arg.type() == typeid(uint8_t))
			{
				uint8_t temp = std::any_cast<uint8_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			else if (arg.type() == typeid(int16_t))
			{
				int16_t temp = std::any_cast<int16_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			else if (arg.type() == typeid(uint16_t))
			{
				uint16_t temp = std::any_cast<uint16_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			else if (arg.type() == typeid(int32_t))
			{
				int32_t temp = std::any_cast<int32_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			else if (arg.type() == typeid(uint32_t))
			{
				uint32_t temp = std::any_cast<uint32_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			else if (arg.type() == typeid(int64_t))
			{
				int64_t temp = std::any_cast<int64_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			else if (arg.type() == typeid(uint64_t))
			{
				uint64_t temp = std::any_cast<uint64_t>(arg);
				std::memcpy(&reg, &temp, sizeof(temp));
			}
			std::memcpy(&data, &reg, sizeof(reg));
			offset += sizeof(reg);
			num++;
		}

		if (num > 6)
		{
			throw std::runtime_error("librpc: too many call arguments");
		}
		SendCMDPacket(CMDS::CMD_PROC_CALL, CMD_PROC_CALL_PACKET_SIZE, {data});

		CheckStatus();

		uint64_t rax = *(int64_t*)&ReceiveData(PROC_CALL_SIZE)[3];
		return rax;
	}

	void PS4DBG::LoadElf(int32_t pid, const std::vector<uint8_t> &elf)
	{

		SendCMDPacket(CMDS::CMD_PROC_ELF, CMD_PROC_ELF_PACKET_SIZE, { pid, elf.size() });
		SendData(elf, elf.size());
		CheckStatus();
	}

	void PS4DBG::LoadElf(int32_t pid, const std::string &filePath)
	{
		CheckConnected();

		std::vector<uint8_t> elf;
		std::ifstream file(filePath);
		if (!file.eof() && !file.fail())
		{
			file.seekg(0, std::ios_base::end);
			std::streampos fileSize = file.tellg();
			elf.resize(fileSize);

			file.seekg(0, std::ios_base::beg);
			file.read((char*)&elf[0], fileSize);
		}
		if (!elf.empty())
		{
			LoadElf(pid, elf);
		}
	}

	void PS4DBG::ChangeProtection(int32_t pid, uint64_t address, uint32_t length, VM_PROTECTIONS newProt)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_PROC_PROTECT, CMD_PROC_PROTECT_PACKET_SIZE, { pid, address, length, (uint32_t)newProt });
		CheckStatus();
	}
	
	ProcessInfo PS4DBG::GetProcessInfo(int32_t pid)
	{
		CheckConnected();
		SendCMDPacket(CMDS::CMD_PROC_INFO, CMD_PROC_INFO_PACKET_SIZE, { pid });
		CheckStatus();

		ProcessInfo data;
		recv(sock, (char*)&data, PROC_PROC_INFO_SIZE, 0);
		return data;
	}

	uint64_t PS4DBG::AllocateMemory(int32_t pid, int32_t length)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_PROC_ALLOC, CMD_PROC_ALLOC_PACKET_SIZE, { pid, length });
		CheckStatus();
		uint64_t data;
		recv(sock, (char*)&data, 8, 0);
		return data;
	}

	void PS4DBG::FreeMemory(int32_t pid, uint64_t address, int32_t length)
	{
		CheckConnected();
		SendCMDPacket(CMDS::CMD_PROC_FREE, CMD_PROC_FREE_PACKET_SIZE, { pid, address, length });
		CheckStatus();
	}

#pragma endregion

#pragma  region Kernel
	uint64_t PS4DBG::KernelBase()
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_KERN_BASE, 0);
		CheckStatus();
		std::vector<uint8_t> data(KERN_BASE_SIZE);
		return *reinterpret_cast<const uint64_t*>(&data[0]);
	}

	std::vector<uint8_t> PS4DBG::KernelReadMemory(uint64_t address, int32_t length)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_KERN_READ, CMD_KERN_READ_PACKET_SIZE, {address, length});
		CheckStatus();
		return ReceiveData(length);
	}

	void PS4DBG::KernelWriteMemory(uint64_t address, const std::vector<uint8_t> &data)
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_KERN_WRITE, CMD_KERN_WRITE_PACKET_SIZE, { address, data.size() });
		CheckStatus();
		SendData(data, data.size());
		CheckStatus();
	}
#pragma endregion

#pragma  region Console
	void PS4DBG::Reboot()
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_CONSOLE_REBOOT, 0);
		shutdown(sock, 2);
		CloseSocket(sock);
	}

	void PS4DBG::Print(const std::string &str)
	{
		CheckConnected();

		int32_t length = (int32_t)str.length() + 1;
		std::vector<uint8_t> data(str.begin(), str.end());
		data.push_back(0);
		SendCMDPacket(CMDS::CMD_CONSOLE_PRINT, CMD_CONSOLE_PRINT_PACKET_SIZE, {length});
		SendData(data, length);
		CheckStatus();
	}

	void PS4DBG::Notify(int32_t messageType, const std::string &message)
	{
		CheckConnected();

		int32_t length = (int32_t)message.length() + 1;
		std::vector<uint8_t> data(message.begin(), message.end());
		data.push_back(0);
		SendCMDPacket(CMDS::CMD_CONSOLE_NOTIFY, CMD_CONSOLE_NOTIFY_PACKET_SIZE, { messageType, length });
		SendData(data, length);
		CheckStatus();
	}

#pragma endregion

#pragma  region Debug
	void PS4DBG::DebuggerThread(DebuggerInterruptCallback callback)
	{
		sockaddr_in serv;
		sockaddr_in client;
		serv.sin_addr.s_addr = INADDR_ANY;
		serv.sin_family = AF_INET;
		serv.sin_port = htons(PS4DBG_DEBUG_PORT);
		Socket	debugServer = socket(AF_INET, SOCK_STREAM, 0);
		bind(debugServer, (sockaddr*)&serv, sizeof(serv));
		listen(debugServer, 0);
		debugging = true;
		int32_t size = sizeof(client);
		Socket cl = accept(debugServer, (sockaddr*)&client, (socklen_t*)&size);
		int32_t i = 1;
		setsockopt(cl, IPPROTO_TCP, 0x01 /*TCP_NODELAY*/, (char *)&i, sizeof(i));
		u_long iMode = 0;
		SocketAvailable(cl, FIONBIO, &iMode);
		while(IsDebugging())
		{
			uint64_t count = 0;
#if defined(PLATFORM_WINDOWS)
			SocketAvailable(cl, FIONREAD, (u_long *)&count);
#elif defined(PLATFORM_LINUX) || defined(PLATFORM_APPLE)
			ioctl(sock, FIONREAD, &count);
#endif

			if (count == DEBUG_INTERRUPT_SIZE)
			{
				std::vector <uint8_t> data(DEBUG_INTERRUPT_SIZE);
				int32_t bytes = recv(cl, (char*)data.data(), DEBUG_INTERRUPT_SIZE, 0);
				if (bytes == DEBUG_INTERRUPT_SIZE)
				{
					DebuggerInterruptPacket packet;
					std::memcpy(&packet, data.data(), sizeof(DebuggerInterruptPacket));
					callback(packet.lwpid, packet.status, std::string((char*)&packet.tdname[0]), packet.reg64, packet.savefpu, packet.dbreg64);
				}
			}
		}
	}
	void PS4DBG::AttachDebugger(int pid, DebuggerInterruptCallback callback)
	{
		CheckConnected();

		
		if (debugging || debugThread.joinable())
		{
			throw ("libdbg: debugger already running?");
		}

		debugging  = false;

		debugThread = std::thread(&PS4DBG::DebuggerThread, this, callback);

		// wait until server is started
		while (!IsDebugging())
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

		SendCMDPacket(CMDS::CMD_DEBUG_ATTACH, CMD_DEBUG_ATTACH_PACKET_SIZE, { pid });
		CheckStatus();
	}

	void PS4DBG::DetachDebugger()
	{
		CheckConnected();

		SendCMDPacket(CMDS::CMD_DEBUG_DETACH, 0);
		CheckStatus();
		
		if (debugging && debugThread.joinable())
		{
			debugging = false;
			debugThread.join();
		}
	}
	void PS4DBG::ProcessStop()
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_STOPGO, CMD_DEBUG_STOPGO_PACKET_SIZE, { 1 });
		CheckStatus();
	}
	void PS4DBG::ProcessKill()
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_STOPGO, CMD_DEBUG_STOPGO_PACKET_SIZE, { 2 });
		CheckStatus();
	}
	void PS4DBG::ProcessResume()
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_STOPGO, CMD_DEBUG_STOPGO_PACKET_SIZE, { 0 });
		CheckStatus();
	}
	void PS4DBG::ChangeBreakpoint(int32_t index, bool enabled, uint64_t address)
	{
		CheckConnected();
		CheckDebugging();

		if (index >= MAX_BREAKPOINTS)
		{
			throw ("libdbg: breakpoint index out of range");
		}

		SendCMDPacket(CMDS::CMD_DEBUG_BREAKPT, CMD_DEBUG_BREAKPT_PACKET_SIZE, { index, (int32_t)enabled, address });
		CheckStatus();
	}
	void PS4DBG::ChangeWatchpoint(int32_t index, bool enabled, WATCHPT_LENGTH length, WATCHPT_BREAKTYPE breaktype, uint64_t address)
	{
		CheckConnected();
		CheckDebugging();

		if (index >= MAX_WATCHPOINTS)
		{
			throw ("libdbg: watchpoint index out of range");
		}

		SendCMDPacket(CMDS::CMD_DEBUG_WATCHPT, CMD_DEBUG_WATCHPT_PACKET_SIZE, { index, (int32_t)enabled, (uint32_t)length, (uint32_t)breaktype, address });
		CheckStatus();
	}

	std::vector<uint32_t> PS4DBG::GetThreadList()
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_THREADS, 0);
		CheckStatus();

		int32_t number;
		int32_t number2;
		recv(sock,(char*)&number, sizeof(int32_t), 0);
		recv(sock, (char*)&number2, sizeof(int32_t), 0);

		std::vector<uint8_t> temp = ReceiveData(number2 * sizeof(uint32_t));
		std::vector<uint32_t> data(number2);
		std::memcpy(data.data(), temp.data(), temp.size());
		return data;
	}

	ThreadInfo PS4DBG::GetThreadInfo(uint32_t lwpid)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_THRINFO, CMD_DEBUG_THRINFO_PACKET_SIZE, { lwpid });
		CheckStatus();

		return *reinterpret_cast<ThreadInfo*>(ReceiveData(DEBUG_THRINFO_SIZE).data());
	}

	void PS4DBG::StopThread(uint32_t lwpid)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_STOPTHR, CMD_DEBUG_STOPTHR_PACKET_SIZE, { lwpid });
		CheckStatus();
	}

	void PS4DBG::ResumeThread(uint32_t lwpid)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_RESUMETHR, CMD_DEBUG_RESUMETHR_PACKET_SIZE, { lwpid });
		CheckStatus();
	}

	regs PS4DBG::GetRegisters(uint32_t lwpid)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_GETREGS, CMD_DEBUG_GETREGS_PACKET_SIZE, { lwpid });
		CheckStatus();

		return *reinterpret_cast<regs*>(ReceiveData(DEBUG_REGS_SIZE).data());
	}

	void PS4DBG::SetRegisters(uint32_t lwpid, regs regs)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_SETREGS, CMD_DEBUG_SETREGS_PACKET_SIZE, { lwpid, DEBUG_REGS_SIZE });
		CheckStatus();
		std::vector<uint8_t> data(sizeof(regs));
		std::memcpy(data.data(), &regs, sizeof(regs));
		SendData(data, DEBUG_REGS_SIZE);
		CheckStatus();
	}

	fpregs PS4DBG::GetFloatRegisters(uint32_t lwpid)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_GETFPREGS, CMD_DEBUG_GETREGS_PACKET_SIZE, { lwpid });
		CheckStatus();

		return *reinterpret_cast<fpregs*>(ReceiveData(DEBUG_FPREGS_SIZE).data());
	}

	void PS4DBG::SetFloatRegisters(uint32_t lwpid, fpregs fpregs)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_SETFPREGS, CMD_DEBUG_SETREGS_PACKET_SIZE, { lwpid, DEBUG_FPREGS_SIZE });
		CheckStatus();
		std::vector<uint8_t> data(sizeof(fpregs));
		std::memcpy(data.data(), &fpregs, sizeof(fpregs));
		SendData(data, DEBUG_FPREGS_SIZE);
		CheckStatus();
	}

	dbregs PS4DBG::GetDebugRegisters(uint32_t lwpid)
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_GETDBGREGS, CMD_DEBUG_GETREGS_PACKET_SIZE, { lwpid });
		CheckStatus();

		return *reinterpret_cast<dbregs*>(ReceiveData(DEBUG_DBGREGS_SIZE).data());
	}

	void PS4DBG::SetDebugRegisters(uint32_t lwpid, dbregs dbregs)
	{
		CheckConnected();
		CheckDebugging();
		std::vector<uint8_t> data(sizeof(dbregs));
		std::memcpy(data.data(), &dbregs, sizeof(dbregs));
		SendCMDPacket(CMDS::CMD_DEBUG_SETDBGREGS, CMD_DEBUG_SETREGS_PACKET_SIZE, { lwpid, DEBUG_DBGREGS_SIZE });
		CheckStatus();
		SendData(data, DEBUG_DBGREGS_SIZE);
		CheckStatus();
	}

	void PS4DBG::SingleStep()
	{
		CheckConnected();
		CheckDebugging();

		SendCMDPacket(CMDS::CMD_DEBUG_SINGLESTEP, 0);
		CheckStatus();
	}

#pragma endregion
	
}

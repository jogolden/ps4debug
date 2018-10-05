using System.Runtime.InteropServices;

namespace libdebug
{
    public class Process
    {
        public string name;
        public int pid;

        /// <summary>
        /// Initializes Process class
        /// </summary>
        /// <param name="name">Process name</param>
        /// <param name="pid">Process ID</param>
        /// <returns></returns>
        public Process(string name, int pid)
        {
            this.name = name;
            this.pid = pid;
        }
        public override string ToString()
        {
            return $"[{pid}] {name}";
        }
    }

    public class ProcessList
    {
        public Process[] processes;

        /// <summary>
        /// Initializes ProcessList class
        /// </summary>
        /// <param name="number">Number of processes</param>
        /// <param name="names">Process names</param>
        /// <param name="pids">Process IDs</param>
        /// <returns></returns>
        public ProcessList(int number, string[] names, int[] pids)
        {
            processes = new Process[number];
            for (int i = 0; i < number; i++)
            {
                processes[i] = new Process(names[i], pids[i]);
            }
        }

        /// <summary>
        /// Finds a process based off name
        /// </summary>
        /// <param name="name">Process name</param>
        /// <param name="contains">Condition to check if process name contains name</param>
        /// <returns></returns>
        public Process FindProcess(string name, bool contains = false)
        {
            foreach (Process p in processes)
            {
                if (contains)
                {
                    if (p.name.Contains(name))
                    {
                        return p;
                    }
                }
                else
                {
                    if (p.name == name)
                    {
                        return p;
                    }
                }
            }

            return null;
        }
    }

    public class MemoryEntry
    {
        public string name;
        public ulong start;
        public ulong end;
        public ulong offset;
        public uint prot;
    }

    public class ProcessMap
    {
        public int pid;
        public MemoryEntry[] entries;

        /// <summary>
        /// Initializes ProcessMap class with memory entries and process ID
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="entries">Process memory entries</param>
        /// <returns></returns>
        public ProcessMap(int pid, MemoryEntry[] entries)
        {
            this.pid = pid;
            this.entries = entries;
        }

        /// <summary>
        /// Finds a virtual memory entry based off name
        /// </summary>
        /// <param name="name">Virtual memory entry name</param>
        /// <param name="contains">Condition to check if entry name contains name</param>
        /// <returns></returns>
        public MemoryEntry FindEntry(string name, bool contains = false)
        {
            foreach (MemoryEntry entry in entries)
            {
                if (contains)
                {
                    if (entry.name.Contains(name))
                    {
                        return entry;
                    }
                }
                else
                {
                    if (entry.name == name)
                    {
                        return entry;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Finds a virtual memory entry based off size
        /// </summary>
        /// <param name="size">Virtual memory entry size</param>
        /// <returns></returns>
        public MemoryEntry FindEntry(ulong size)
        {
            foreach (MemoryEntry entry in entries)
            {
                if ((entry.start - entry.end) == size)
                {
                    return entry;
                }
            }

            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct ProcessInfo
    {
        public int pid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)]
        public string name;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string path;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string titleid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string contentid;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct ThreadInfo
    {
        public int pid;
        public int priority;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string name;
    }
}
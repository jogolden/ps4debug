using System.Runtime.InteropServices;

namespace libdebug
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct regs
    {
        public ulong r_r15;
        public ulong r_r14;
        public ulong r_r13;
        public ulong r_r12;
        public ulong r_r11;
        public ulong r_r10;
        public ulong r_r9;
        public ulong r_r8;
        public ulong r_rdi;
        public ulong r_rsi;
        public ulong r_rbp;
        public ulong r_rbx;
        public ulong r_rdx;
        public ulong r_rcx;
        public ulong r_rax;
        public uint r_trapno;
        public ushort r_fs;
        public ushort r_gs;
        public uint r_err;
        public ushort r_es;
        public ushort r_ds;
        public ulong r_rip;
        public ulong r_cs;
        public ulong r_rflags;
        public ulong r_rsp;
        public ulong r_ss;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct envxmm
    {
        public ushort en_cw; /* control word (16bits) */
        public ushort en_sw; /* status word (16bits) */
        public byte en_tw; /* tag word (8bits) */
        public byte en_zero;
        public ushort en_opcode; /* opcode last executed (11 bits ) */
        public ulong en_rip; /* floating point instruction pointer */
        public ulong en_rdp; /* floating operand pointer */
        public uint en_mxcsr; /* SSE sontorol/status register */
        public uint en_mxcsr_mask; /* valid bits in mxcsr */
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct acc
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public byte[] fp_bytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        private byte[] fp_pad;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct xmmacc
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] xmm_bytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ymmacc
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ymm_bytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct xstate_hdr
    {
        public ulong xstate_bv;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        private byte[] xstate_rsrv0;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
        private byte[] xstate_rsrv;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct savefpu_xstate
    {
        public xstate_hdr sx_hd;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public ymmacc[] sx_ymm;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 64)]
    public struct fpregs
    {
        public envxmm svn_env;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public acc[] sv_fp;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public xmmacc[] sv_xmm;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        private byte[] sv_pad;
        public savefpu_xstate sv_xstate;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct dbregs
    {
        public ulong dr0;
        public ulong dr1;
        public ulong dr2;
        public ulong dr3;
        public ulong dr4;
        public ulong dr5;
        public ulong dr6;
        public ulong dr7;
        public ulong dr8;
        public ulong dr9;
        public ulong dr10;
        public ulong dr11;
        public ulong dr12;
        public ulong dr13;
        public ulong dr14;
        public ulong dr15;
    }
}
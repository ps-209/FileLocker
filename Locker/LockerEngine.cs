using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace FileLocker.Locker
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void ProgressCallback(float progress);
    internal class LockerEngine
    {
        private const string DllPath = @"Locker\filelocker.dll";
        [DllImport(DllPath, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern byte dll_locking([MarshalAs(UnmanagedType.LPWStr)] string srcPath, [MarshalAs(UnmanagedType.LPStr)] string password, long totalSize, ProgressCallback callback);

        [DllImport(DllPath, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern byte dll_unlocking([MarshalAs(UnmanagedType.LPWStr)] string lockFilePath,[MarshalAs(UnmanagedType.LPStr)] string password, long totalSize, ProgressCallback callback);
    }
}

/* Copyright (C) 2014-2015, Manuel Meitinger
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Aufbauwerk.Tools.KioskControl
{
    static class Win32
    {
        public sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            SafeProcessHandle() : base(true) { }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }

        public const uint SI_EDIT_PERMS = 0x00000000;
        public const uint SI_ADVANCED = 0x00000010;
        public const uint SI_NO_ACL_PROTECT = 0x00000200;
        public const uint DACL_SECURITY_INFORMATION = 0x00000004;
        public const uint SI_ACCESS_GENERAL = 0x00020000;
        public const uint SI_ACCESS_SPECIFIC = 0x00010000;
        public const ushort SE_SELF_RELATIVE = 0x8000;
        public const ushort SE_DACL_PRESENT = 0x0004;
        public const uint MAXIMUM_ALLOWED = 0x02000000;
        public const uint LMEM_FIXED = 0x0000;
        public const int PROCESS_TERMINATE = 0x0001;
        public const uint WRITE_DAC =0x00040000;
        public const uint READ_CONTROL = 0x00020000;

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        public static extern bool CloseHandle
        (
            IntPtr hObject
        );

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess
        (
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId
        );

        [DllImport("kernel32", ExactSpelling = true)]
        public static extern uint GetCurrentProcessId();

        [DllImport("advapi32", ExactSpelling = true)]
        public static extern int GetSecurityDescriptorLength
        (
            IntPtr pSecurityDescriptor
        );

        [DllImport("advapi32", ExactSpelling = true, SetLastError = true)]
        public static extern bool MakeSelfRelativeSD
        (
            IntPtr pAbsoluteSD,
            IntPtr pSelfRelativeSD,
            ref int lpdwBufferLength
        );

        [DllImport("advapi32", ExactSpelling = true, SetLastError = true)]
        public static extern bool GetSecurityDescriptorControl
        (
            IntPtr pSecurityDescriptor,
            out ushort pControl,
            out uint lpdwRevision
        );

        [DllImport("advapi32", ExactSpelling = true, SetLastError = true)]
        public static extern bool AccessCheck
        (
            IntPtr pSecurityDescriptor,
            IntPtr ClientToken,
            uint DesiredAccess,
            ref GENERIC_MAPPING GenericMapping,
            ref PRIVILEGE_SET PrivilegeSet,
            ref int PrivilegeSetLength,
            out uint GrantedAccess,
            out bool AccessStatus
        );

        [DllImport("kernel32", EntryPoint = "RtlMoveMemory")]
        public static extern void MoveMemory
        (
            IntPtr Destination,
            IntPtr Source,
            int Length
        );

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr LocalAlloc
        (
            uint uFlags,
            int uBytes
        );

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr LocalFree
        (
            IntPtr hMem
        );

        [DllImport("aclui", ExactSpelling = true, SetLastError = true)]
        public static extern bool EditSecurity
        (
            IntPtr hwndOwner,
            ISecurityInformation psi
        );

        [DllImport("advapi32", ExactSpelling = true, SetLastError = true)]
        public static extern void MapGenericMask
        (
            ref uint AccessMask,
            ref GENERIC_MAPPING GenericMapping
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET
        {
            public int PrivilegeCount;
            public uint Control;
            public LUID_AND_ATTRIBUTES Privilege;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GENERIC_MAPPING
        {
            public uint GenericRead;
            public uint GenericWrite;
            public uint GenericExecute;
            public uint GenericAll;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SI_OBJECT_INFO
        {
            public uint dwFlags;
            public IntPtr hInstance;
            public IntPtr pszServerName;
            public IntPtr pszObjectName;
            public IntPtr pszPageTitle;
            public Guid guidObjectType;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SI_ACCESS
        {
            public IntPtr pguid;
            public uint mask;
            public IntPtr pszName;
            public uint dwFlags;
        }

        [Guid("965FC360-16FF-11d0-91CB-00AA00BBB723")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface ISecurityInformation
        {
            void GetObjectInformation([Out] out SI_OBJECT_INFO pObjectInfo);
            void GetSecurity([In] uint RequestedInformation, [Out] out IntPtr ppSecurityDescriptor, [In] bool fDefault);
            void SetSecurity([In] uint SecurityInformation, [In] IntPtr pSecurityDescriptor);
            void GetAccessRights([In] IntPtr pguidObjectType, [In] uint dwFlags, [Out] out IntPtr ppAccess, [Out] out int pcAccesses, [Out] out int piDefaultAccess);
            void MapGeneric([In] IntPtr pguidObjectType, [In] IntPtr pAceFlags, [In, Out] ref uint pMask);
            void GetInheritTypes([Out] out IntPtr ppInheritTypes, [Out] out int pcInheritTypes);
            void PropertySheetPageCallback([In] IntPtr hwnd, [In] uint uMsg, [In] uint uPage);
        }
    }
}

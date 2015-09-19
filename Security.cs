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
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Aufbauwerk.Tools.KioskControl
{
    [Flags]
    public enum SessionRights
    {
        Connect = 0x1,
        View = 0x2,
        Interact = 0x4,
        ConnectToClient = 0x10,
        CreateVirtualChannel = 0x20,
    }

    public class ProcessSecurity : NativeObjectSecurity
    {
        class ProcessAccessRule : AccessRule
        {
            public ProcessAccessRule(IdentityReference identity, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
                : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, type) { }
        }

        ProcessSecurity(Win32.SafeProcessHandle handle) : base(true, ResourceType.KernelObject, handle, AccessControlSections.Access) { }

        public static void ProtectCurrentProcessFromTerminate()
        {
            // denies the current user terminate permissions on the current process
            using (var process = Win32.OpenProcess(Win32.READ_CONTROL | Win32.WRITE_DAC, false, Win32.GetCurrentProcessId()))
            {
                if (process.IsInvalid)
                    throw new Win32Exception();
                var security = new ProcessSecurity(process);
                using (var identity = WindowsIdentity.GetCurrent())
                    security.AddAccessRule(new ProcessAccessRule(identity.User, Win32.PROCESS_TERMINATE, false, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));
                security.WriteLock();
                try { security.Persist(process, AccessControlSections.Access); }
                finally { security.WriteUnlock(); }
            }
        }

        public override Type AccessRightType
        {
            get { return typeof(int); }
        }

        public override AccessRule AccessRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
        {
            return new ProcessAccessRule(identityReference, accessMask, isInherited, inheritanceFlags, propagationFlags, type);
        }

        public override Type AccessRuleType
        {
            get { return typeof(ProcessAccessRule); }
        }

        public override AuditRule AuditRuleFactory(System.Security.Principal.IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
        {
            throw new NotImplementedException();
        }

        public override Type AuditRuleType
        {
            get { throw new NotImplementedException(); }
        }
    }

    public class Security : Win32.ISecurityInformation
    {
        static readonly Win32.GENERIC_MAPPING genericMapping = new Win32.GENERIC_MAPPING()
        {
            GenericRead = (uint)(SessionRights.Connect | SessionRights.View),
            GenericWrite = (uint)(SessionRights.Connect | SessionRights.View | SessionRights.Interact),
            GenericExecute = (uint)(SessionRights.Connect | SessionRights.CreateVirtualChannel),
            GenericAll = (uint)(SessionRights.Connect | SessionRights.View | SessionRights.Interact | SessionRights.ConnectToClient | SessionRights.CreateVirtualChannel),
        };

        static bool IsGuidNullOrEmpty(IntPtr pointerToGuid)
        {
            // determine if the given pointer to a guid is null or the guid is empty
            return pointerToGuid == IntPtr.Zero || (Guid)Marshal.PtrToStructure(pointerToGuid, typeof(Guid)) == Guid.Empty;
        }

        static ushort GetSDControl(IntPtr sd)
        {
            // shortcut method to get the sd's control flags
            var control = (ushort)0;
            var revision = (uint)0;
            if (!Win32.GetSecurityDescriptorControl(sd, out control, out revision))
                throw new Win32Exception();
            return control;
        }

        static IntPtr CloneSD(IntPtr sd)
        {
            // ensure the sd is not null
            if (sd == IntPtr.Zero)
                return IntPtr.Zero;

            // allocate the necessary space
            var len = Win32.GetSecurityDescriptorLength(sd);
            var clone = Win32.LocalAlloc(Win32.LMEM_FIXED, len);
            if (clone == IntPtr.Zero)
                throw new Win32Exception();

            // convert an absolute sd or just move the memory if it's already self-relative
            if ((GetSDControl(sd) & Win32.SE_SELF_RELATIVE) != 0)
                Win32.MoveMemory(clone, sd, len);
            else if (!Win32.MakeSelfRelativeSD(sd, clone, ref len))
                throw new Win32Exception();
            return clone;
        }

        public static IntPtr SddlToSid(string sddl)
        {
            // convert the sddl and set the owner and group
            var rawSd = new RawSecurityDescriptor(sddl);
            using (var identity = WindowsIdentity.GetCurrent())
            {
                rawSd.Owner = identity.User;
                rawSd.Group = (SecurityIdentifier)identity.Groups[0].Translate(typeof(SecurityIdentifier));
            }

            // convert the managed sd into local heap buffer
            var buffer = new byte[rawSd.BinaryLength];
            rawSd.GetBinaryForm(buffer, 0);
            var newSd = Win32.LocalAlloc(Win32.LMEM_FIXED, buffer.Length);
            if (newSd == IntPtr.Zero)
                throw new Win32Exception();
            Marshal.Copy(buffer, 0, newSd, buffer.Length);
            return newSd;
        }

        public static string SidToSddl(IntPtr sid)
        {
            // return the DACL part of the SID as SDDL
            var buffer = new byte[Win32.GetSecurityDescriptorLength(sid)];
            Marshal.Copy(sid, buffer, 0, buffer.Length);
            return new RawSecurityDescriptor(buffer, 0).GetSddlForm(AccessControlSections.Access);
        }

        public static SessionRights GetEffectivePermissions(IntPtr clientToken)
        {
            // check the token
            if (clientToken == IntPtr.Zero)
                throw new ArgumentNullException("clientToken");

            // if there is no dacl, grant everything
            var sd = Program.SecurityDescriptor;
            if ((GetSDControl(sd) & Win32.SE_DACL_PRESENT) == 0)
                return (SessionRights)genericMapping.GenericAll;

            // get the maximum allowed permissions
            var mapping = genericMapping;
            var dummy = new Win32.PRIVILEGE_SET();
            var dummyLen = Marshal.SizeOf(typeof(Win32.PRIVILEGE_SET));
            var granted = 0U;
            var result = false;
            if (!Win32.AccessCheck(sd, clientToken, Win32.MAXIMUM_ALLOWED, ref mapping, ref dummy, ref dummyLen, out granted, out result))
                throw new Win32Exception();
            return result ? (SessionRights)granted : 0;
        }

        public static void ShowEditDialog()
        {
            // show the edit dialog
            if (!Win32.EditSecurity(IntPtr.Zero, new Security()))
                throw new Win32Exception();
        }

        IntPtr objectName;
        GCHandle accessRightsHandle;

        Security() { }

        void Win32.ISecurityInformation.GetObjectInformation(out Win32.SI_OBJECT_INFO pObjectInfo)
        {
            // return the session object information
            if (objectName == IntPtr.Zero)
                objectName = Marshal.StringToHGlobalUni("Kiosk Session");
            pObjectInfo = new Win32.SI_OBJECT_INFO()
            {
                dwFlags = Win32.SI_EDIT_PERMS | Win32.SI_ADVANCED | Win32.SI_NO_ACL_PROTECT,
                pszObjectName = objectName,
            };
        }

        void Win32.ISecurityInformation.GetSecurity(uint RequestedInformation, out IntPtr ppSecurityDescriptor, bool fDefault)
        {
            if (fDefault) // reset is not implemented
                throw new NotImplementedException();
            if ((RequestedInformation & (~Win32.DACL_SECURITY_INFORMATION)) != 0) // only dacl is supported
                throw new NotSupportedException();
            ppSecurityDescriptor = RequestedInformation != 0 ? CloneSD(Program.SecurityDescriptor) : IntPtr.Zero;
        }

        void Win32.ISecurityInformation.SetSecurity(uint SecurityInformation, IntPtr pSecurityDescriptor)
        {
            if ((SecurityInformation & (~Win32.DACL_SECURITY_INFORMATION)) != 0) // only dacl is supporteds
                throw new NotSupportedException();
            if (SecurityInformation != 0)
                Program.SecurityDescriptor = CloneSD(pSecurityDescriptor);
        }

        void Win32.ISecurityInformation.GetAccessRights(IntPtr pguidObjectType, uint dwFlags, out IntPtr ppAccess, out int pcAccesses, out int piDefaultAccess)
        {
            // return the an empty array if the session object wasn't queried
            if (!IsGuidNullOrEmpty(pguidObjectType))
            {
                ppAccess = IntPtr.Zero;
                pcAccesses = 0;
                piDefaultAccess = -1;
                return;
            }

            // create the access rights array if necessary
            if (!accessRightsHandle.IsAllocated)
            {
                var accessRightsList = new List<Win32.SI_ACCESS>()
                {
                    new Win32.SI_ACCESS()
                    {
                         pguid = IntPtr.Zero,
                         mask = genericMapping.GenericRead,
                         pszName = Marshal.StringToHGlobalUni("View Only"),
                         dwFlags = Win32.SI_ACCESS_GENERAL
                    },
                    new Win32.SI_ACCESS()
                    {
                         pguid = IntPtr.Zero,
                         mask = genericMapping.GenericWrite,
                         pszName = Marshal.StringToHGlobalUni("Interactive"),
                         dwFlags = Win32.SI_ACCESS_GENERAL
                    },
                    new Win32.SI_ACCESS()
                    {
                         pguid = IntPtr.Zero,
                         mask = genericMapping.GenericAll,
                         pszName = Marshal.StringToHGlobalUni("Full"),
                         dwFlags = Win32.SI_ACCESS_GENERAL
                    }
                };
                foreach (var right in Enum.GetValues(typeof(SessionRights)))
                {
                    accessRightsList.Add(new Win32.SI_ACCESS()
                    {
                        pguid = IntPtr.Zero,
                        mask = (uint)(SessionRights)right,
                        pszName = Marshal.StringToHGlobalUni(Enum.GetName(typeof(SessionRights), right)),
                        dwFlags = Win32.SI_ACCESS_SPECIFIC
                    });
                }
                accessRightsHandle = GCHandle.Alloc(accessRightsList.ToArray(), GCHandleType.Pinned);
            }

            // returned the pinned address and the rights element count
            ppAccess = accessRightsHandle.AddrOfPinnedObject();
            pcAccesses = ((Win32.SI_ACCESS[])accessRightsHandle.Target).Length;
            piDefaultAccess = 0;
        }

        void Win32.ISecurityInformation.MapGeneric(IntPtr pguidObjectType, IntPtr pAceFlags, ref uint pMask)
        {
            // call the mapping function if the session rights are to be mapped
            if (!IsGuidNullOrEmpty(pguidObjectType))
            {
                var mapping = genericMapping;
                Win32.MapGenericMask(ref pMask, ref mapping);
            }
        }

        void Win32.ISecurityInformation.GetInheritTypes(out IntPtr ppInheritTypes, out int pcInheritTypes)
        {
            // no inherited types
            ppInheritTypes = IntPtr.Zero;
            pcInheritTypes = 0;
        }

        void Win32.ISecurityInformation.PropertySheetPageCallback(IntPtr hwnd, uint uMsg, uint uPage)
        {
            // don't care
        }
    }
}

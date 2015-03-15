/* Copyright (C) 2014, Manuel Meitinger
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
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceModel.Web;
using System.Windows.Forms;
using System.Xml;
using RDPCOMAPILib;

namespace Aufbauwerk.Tools.KioskControl
{
    static class Program
    {
        static string configFile = null;
        static IntPtr sd = IntPtr.Zero;
        static DateTime sdTime;

        static void ReloadSecurityDescriptor()
        {
            // convert the string to managed sd
            var settings = Properties.Settings.Default;
            settings.Reload();
            var rawSd = new RawSecurityDescriptor(settings.Security);
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
            sd = newSd; // NOTE: we are leaking here, but since the config file won't change a lot it's ok
            sdTime = DateTime.UtcNow;
        }

        internal static IntPtr SecurityDescriptor
        {
            get
            {
                // ensure initialized
                if (configFile == null)
                    throw new InvalidOperationException();

                // check if there already is an sd
                if (sd != IntPtr.Zero)
                {
                    try
                    {
                        // try to reload it if necessary
                        if (File.GetLastWriteTimeUtc(configFile) > sdTime)
                            ReloadSecurityDescriptor();
                    }
                    catch { }
                }
                else
                    // load the sd
                    ReloadSecurityDescriptor();
                return sd;
            }

            set
            {
                // ensure initialized
                if (configFile == null)
                    throw new InvalidOperationException();

                // check the sd and convert it into a string
                if (value == IntPtr.Zero)
                    throw new ArgumentNullException("SecurityDescriptor");
                var str = string.Empty;
                var strPtr = IntPtr.Zero;
                var strLen = 0;
                if (!Win32.ConvertSecurityDescriptorToStringSecurityDescriptor(value, Win32.SDDL_REVISION_1, Win32.DACL_SECURITY_INFORMATION, out strPtr, out strLen))
                    throw new Win32Exception();
                try { str = Marshal.PtrToStringAuto(strPtr, strLen).TrimEnd('\0'); }
                finally { Win32.LocalFree(strPtr); }

                // store the security string
                var settings = new XmlDocument();
                settings.Load(configFile);
                settings.SelectSingleNode(string.Format(@"/configuration/applicationSettings/{0}/setting[@name='Security']/value", typeof(Properties.Settings).FullName)).InnerText = str;
                settings.Save(configFile);

                // reload the sd
                ReloadSecurityDescriptor();
            }
        }

        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                // enable styles and faster text rendering
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                // parse the args
                bool showSecurityDialog = false;
                string paramShowSecurityDialog = "/editsecurity";
                string overrideConfig = null;
                string paramOverrideConfig = "/useconfiguration:";
                foreach (var arg in args)
                {
                    if (arg.Equals(paramShowSecurityDialog, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!showSecurityDialog)
                        {
                            showSecurityDialog = true;
                            continue;
                        }
                    }
                    if (arg.StartsWith(paramOverrideConfig, StringComparison.OrdinalIgnoreCase))
                    {
                        if (overrideConfig == null)
                        {
                            overrideConfig = arg.Substring(paramOverrideConfig.Length);
                            continue;
                        }
                    }
                    MessageBox.Show(string.Format("{0} [{1}] [{2}]\n\n\n\n{1}\t\tDisplays the security dialog.\n\n{2}\tUse an alternative app config file.", Environment.GetCommandLineArgs()[0], paramShowSecurityDialog, paramOverrideConfig + "<path>"), "Usage", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // set the config file and show the security dialog if requested
                if (overrideConfig != null)
                    ((AppDomainSetup)typeof(AppDomain).GetProperty("FusionStore", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(AppDomain.CurrentDomain, null)).ConfigurationFile = overrideConfig;
                configFile = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
                if (showSecurityDialog)
                {
                    Security.ShowEditDialog();
                    return;
                }

                // create the rdp session
                var session = new RDPSessionClass();
                session.OnError += OnSessionError;
                session.Open();
                try
                {
                    // create the web service host and run the app
                    var host = new WebServiceHost(new Service(session));
                    host.Open();
                    try { Application.Run(); }
                    finally { host.Close(); }
                }
                finally { session.Close(); }
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, e.Source, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.ExitCode = Marshal.GetHRForException(e);
            }
        }

        static void OnSessionError(object ErrorInfo)
        {
            // restart on failure
            Application.Restart();
        }
    }
}

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
using System.Runtime.InteropServices;
using System.ServiceModel.Web;
using System.Windows.Forms;
using System.Xml;
using Aufbauwerk.Tools.KioskControl.Properties;
using RDPCOMAPILib;

namespace Aufbauwerk.Tools.KioskControl
{
    static class Program
    {
        static readonly string configFile = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
        static IntPtr sd = IntPtr.Zero;
        static DateTime sdTime;

        internal static IntPtr SecurityDescriptor
        {
            get
            {
                // check if the security has changed or has never been queried
                var sdCurrentTime = sdTime;
                try { sdCurrentTime = File.GetLastWriteTimeUtc(configFile); }
                catch { }
                if (sd == IntPtr.Zero || sdCurrentTime > sdTime)
                {
                    // convert the string to sd and set the current time
                    var settings = Settings.Default;
                    settings.Reload();
                    var newSd = sd;
                    var size = 0;
                    if (Win32.ConvertStringSecurityDescriptorToSecurityDescriptor(settings.Security, Win32.SDDL_REVISION_1, out newSd, out size))
                    {
                        // free the old sd and set the new one
                        if (sd != IntPtr.Zero)
                            Win32.LocalFree(sd);
                        sd = newSd;
                    }
                    else
                    {
                        // throw an error if there's no older valid sd
                        if (sd == IntPtr.Zero)
                            throw new Win32Exception();
                    }
                    sdTime = sdCurrentTime;
                }
                return sd;
            }

            set
            {
                // set the sd and try to convert it into a string
                if (value == IntPtr.Zero)
                    throw new ArgumentNullException("SecurityDescriptor");
                sd = value;
                var strPtr = IntPtr.Zero;
                var strLen = 0;
                var sdCurrentTime = DateTime.Now;
                if (Win32.ConvertSecurityDescriptorToStringSecurityDescriptor(value, Win32.SDDL_REVISION_1, Win32.DACL_SECURITY_INFORMATION, out strPtr, out strLen))
                {
                    // get the managed string and store it within the config file
                    var str = Marshal.PtrToStringAuto(strPtr, strLen).TrimEnd('\0');
                    Win32.LocalFree(strPtr);
                    var settings = new XmlDocument();
                    settings.Load(configFile);
                    settings.SelectSingleNode(string.Format(@"/configuration/applicationSettings/{0}/setting[@name='Security']/value", typeof(Settings).FullName)).InnerText = str;
                    settings.Save(configFile);
                    try { sdCurrentTime = File.GetLastWriteTimeUtc(configFile); }
                    catch { }
                }
                sdTime = sdCurrentTime;
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

                // either show the edit security dialog if requested
                if (args.Length == 1 && args[0].Trim().Equals("/editsecurity", StringComparison.InvariantCultureIgnoreCase))
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

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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using RDPCOMAPILib;

namespace Aufbauwerk.Tools.KioskControl
{
    public class InvitationData
    {
        static readonly Dictionary<Guid, InvitationData> registered = new Dictionary<Guid, InvitationData>();

        public static IEnumerable<InvitationData> Snapshot
        {
            get
            {
                // create and return a snapshot of all invitation data instances
                lock (registered)
                {
                    var snapshot = new InvitationData[registered.Values.Count];
                    registered.Values.CopyTo(snapshot, 0);
                    return snapshot;
                }
            }
        }

        public static InvitationData FromInvitation(IRDPSRAPIInvitation invitation)
        {
            // check the input
            if (invitation == null)
                throw new ArgumentNullException("invitation");

            // try to convert the invitation's group name into a guid
            var guid = Guid.Empty;
            try { guid = new Guid(invitation.GroupName); }
            catch { return null; }

            // retrieve the invitation data
            lock (registered)
            {
                var data = (InvitationData)null;
                registered.TryGetValue(guid, out data);
                return data;
            }
        }

        public void CreateInvitation(IRDPSRAPISharingSession session, string bstrAuthString, string bstrPassword, int AttendeeLimit)
        {
            // check the input
            if (session == null)
                throw new ArgumentNullException("session");

            // ensure the method hasn't been called yet
            if (Invitation != null)
                throw new InvalidOperationException();

            // get the invitation manager
            var invitationManager = session.Invitations;
            try
            {
                // lock the registration
                lock (registered)
                {
                    // check again within the lock 
                    if (Invitation != null)
                        throw new InvalidOperationException();

                    // find and register a suitable guid
                    var guid = Guid.NewGuid();
                    while (registered.ContainsKey(guid) || guid == Guid.Empty)
                        guid = Guid.NewGuid();
                    registered.Add(guid, this);

                    // create an invitation
                    try { Invitation = invitationManager.CreateInvitation(bstrAuthString, guid.ToString(), bstrPassword, AttendeeLimit); }
                    catch
                    {
                        // if there's an error, release the guid
                        registered.Remove(guid);
                        throw;
                    }
                }
            }
            finally { Marshal.ReleaseComObject(invitationManager); }
        }

        public IRDPSRAPIInvitation Invitation { get; private set; }

        public SecurityIdentifier User { get; set; }

        public SessionRights SessionRights { get; set; }

        public CTRL_LEVEL InitialControlLevel { get; set; }

        public string AttendeeRemoteName { get; set; }

        public Timer ConnectionTimer { get; set; }
    }
}

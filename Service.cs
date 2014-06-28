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
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using System.Threading;
using RDPCOMAPILib;

namespace Aufbauwerk.Tools.KioskControl
{
    [ServiceContract]
    public interface IContract
    {
        [WebGet(UriTemplate = "/{level=max}")]
        [OperationContract]
        Stream WebMain(string level);
    }

    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, ConcurrencyMode = ConcurrencyMode.Multiple)]
    public class Service : IContract
    {
        readonly RDPSession session;
        readonly RandomNumberGenerator rng;

        public Service(RDPSession session)
        {
            // check the input
            if (session == null)
                throw new ArgumentNullException("session");

            // store the session and create the default rng
            this.session = session;
            this.rng = RandomNumberGenerator.Create();

            // hook the session events
            session.OnAttendeeConnected += OnAttendeeConnected;
            session.OnControlLevelChangeRequest += OnControlLevelChangeRequest;
            session.OnAttendeeDisconnected += OnAttendeeDisconnected;
        }

        InvitationData DataFromAttendee(IRDPSRAPIAttendee attendee)
        {
            // shortcut for getting the invitation and then the data
            if (attendee.RemoteName == null)
                return null;
            var invitation = attendee.Invitation;
            try { return InvitationData.FromInvitation(invitation); }
            finally { Marshal.ReleaseComObject(invitation); }
        }

        void OnConnectionTimedOut(object state)
        {
            var data = (InvitationData)state;
            lock (data)
            {
                // bail if the client has already connected
                if (data.ConnectionTimer == null)
                    return;

                // otherwise invalidate the invitation
                data.Invitation.Revoked = true;
                data.AttendeeRemoteName = null;
                data.ConnectionTimer.Dispose();
                data.ConnectionTimer = null;
            }
        }

        void OnAttendeeConnected(object pAttendee)
        {
            var attendee = (IRDPSRAPIAttendee)pAttendee;
            try
            {
                // get the invitation data
                var data = DataFromAttendee(attendee);
                if (data != null)
                {
                    // lock it
                    lock (data)
                    {
                        // test its attendee remote name and make sure it's still waiting for a connection
                        if (data.AttendeeRemoteName == attendee.RemoteName && data.ConnectionTimer != null)
                        {
                            // revoke the invitation (no further connects)
                            data.Invitation.Revoked = true;

                            // clear the connection timer
                            data.ConnectionTimer.Dispose();
                            data.ConnectionTimer = null;

                            // set the initial control level and exit
                            attendee.ControlLevel = data.InitialControlLevel;
                            return;
                        }
                    }
                }

                // terminate the invalid connection
                attendee.TerminateConnection();
            }
            finally { Marshal.ReleaseComObject(attendee); }
        }

        void OnControlLevelChangeRequest(object pAttendee, CTRL_LEVEL RequestedLevel)
        {
            var attendee = (IRDPSRAPIAttendee)pAttendee;
            try
            {
                // get the invitation data
                var data = DataFromAttendee(attendee);
                if (data != null)
                {
                    // lock it
                    lock (data)
                    {
                        // test its attendee remote name
                        if (data.AttendeeRemoteName == attendee.RemoteName)
                        {
                            // only do a permission check if the initial control level wasn't requested
                            if (data.InitialControlLevel != RequestedLevel)
                            {
                                // check the known control levels, exit if the permission is missing
                                switch (RequestedLevel)
                                {
                                    case CTRL_LEVEL.CTRL_LEVEL_NONE:
                                        break;
                                    case CTRL_LEVEL.CTRL_LEVEL_VIEW:
                                        if ((data.SessionRights & SessionRights.View) == 0)
                                            return;
                                        break;
                                    case CTRL_LEVEL.CTRL_LEVEL_INTERACTIVE:
                                        if ((data.SessionRights & SessionRights.Interact) == 0)
                                            return;
                                        break;
                                }
                            }

                            // set the requested control level and exit
                            attendee.ControlLevel = RequestedLevel;
                            return;
                        }
                    }
                }

                // terminate the invalid connection
                attendee.TerminateConnection();
            }
            finally { Marshal.ReleaseComObject(attendee); }
        }

        void OnAttendeeDisconnected(object pDisconnectInfo)
        {
            var info = (IRDPSRAPIAttendeeDisconnectInfo)pDisconnectInfo;
            try
            {
                // get the attendee
                var attendee = info.Attendee;
                try
                {
                    // get the invitation data
                    var data = DataFromAttendee(attendee);
                    if (data != null)
                    {
                        // lock it
                        lock (data)
                        {
                            // clear the remote name if it matches and the viewer has properly connected
                            if (data.AttendeeRemoteName == attendee.RemoteName && data.ConnectionTimer == null)
                                data.AttendeeRemoteName = null;
                        }
                    }
                }
                finally { Marshal.ReleaseComObject(attendee); }
            }
            finally { Marshal.ReleaseComObject(info); }
        }

        CTRL_LEVEL ParseControlLevel(SessionRights perms, string level)
        {
            // check and convert the control level
            switch (level.ToUpperInvariant())
            {
                case "VIEW":
                    if ((perms & SessionRights.View) == 0)
                    {
                        WebOperationContext.Current.OutgoingResponse.StatusCode = HttpStatusCode.Forbidden;
                        return CTRL_LEVEL.CTRL_LEVEL_INVALID;
                    }
                    return CTRL_LEVEL.CTRL_LEVEL_VIEW;
                case "INTERACT":
                    if ((perms & SessionRights.Interact) == 0)
                    {
                        WebOperationContext.Current.OutgoingResponse.StatusCode = HttpStatusCode.Forbidden;
                        return CTRL_LEVEL.CTRL_LEVEL_INVALID;
                    }
                    return CTRL_LEVEL.CTRL_LEVEL_INTERACTIVE;
                case "MAX":
                    if ((perms & SessionRights.Interact) != 0)
                        return CTRL_LEVEL.CTRL_LEVEL_INTERACTIVE;
                    else if ((perms & SessionRights.View) != 0)
                        return CTRL_LEVEL.CTRL_LEVEL_VIEW;
                    else
                        return CTRL_LEVEL.CTRL_LEVEL_NONE;
                default:
                    WebOperationContext.Current.OutgoingResponse.StatusCode = HttpStatusCode.BadRequest;
                    return CTRL_LEVEL.CTRL_LEVEL_INVALID;
            }
        }

        string CreateAttendeeName()
        {
            // create 127 strong random bytes and return them as hex string
            var buffer = new byte[127];
            rng.GetBytes(buffer);
            var builder = new StringBuilder(254);
            for (int i = 0; i < buffer.Length; i++)
                builder.Append(buffer[i].ToString("X2", CultureInfo.InvariantCulture));
            return builder.ToString();
        }

        string EscapeString(string s)
        {
            // convert the string to UTF8 and percent-escape all bytes
            var buffer = Encoding.UTF8.GetBytes(s);
            var builder = new StringBuilder(buffer.Length * 3);
            for (int i = 0; i < buffer.Length; i++)
            {
                builder.Append('%');
                builder.Append(buffer[i].ToString("X2", CultureInfo.InvariantCulture));
            }
            return builder.ToString();
        }

        Stream FinalizeResponse(InvitationData data)
        {
            // create the connection time-out timer
            data.ConnectionTimer = new Timer(OnConnectionTimedOut, data, Properties.Settings.Default.ConnectionTimeout, TimeSpan.Zero);

            // set the caching policy and create the response stream
            WebOperationContext.Current.OutgoingResponse.Headers[HttpResponseHeader.CacheControl] = "no-cache";
            return new MemoryStream
            (
                Encoding.UTF8.GetBytes
                (
                    string.Format
                    (
                        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n" +
                        "<html>\n" +
                        "  <head>\n" +
                        "    <title>{0}</title>\n" +
                        "    <meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"/>\n" +
                        "  </head>\n" +
                        "  <body onload=\"try{{RDPViewer.DisconnectedText=decodeURIComponent('{3}');RDPViewer.Connect(decodeURIComponent('{1}'), '{2}', '');}}catch(e){{alert(e.message);}}\" style=\"margin:0;padding:0;\">\n" +
                        "    <object id=\"RDPViewer\" classid=\"clsid:32be5ed2-5c86-480f-a914-0ff8885a1b3f\" width=\"100%\" height=\"100%\" style=\"border:0;margin:0;padding:0;\"></object>\n" +
                        "  </body>\n" +
                        "</html>",
                        Environment.MachineName,
                        EscapeString(data.Invitation.ConnectionString),
                        data.AttendeeRemoteName,
                        EscapeString(Properties.Settings.Default.DisconnectedText)
                    )
                )
            );
        }

        public Stream WebMain(string level)
        {
            // get the permissions and check if the client can connect
            var sessionRights = Security.GetEffectivePermissions(OperationContext.Current.ServiceSecurityContext.WindowsIdentity.Token);
            if ((sessionRights & SessionRights.Connect) == 0)
            {
                WebOperationContext.Current.OutgoingResponse.StatusCode = HttpStatusCode.Forbidden;
                return null;
            }

            // get the internal control level
            var internalLevel = ParseControlLevel(sessionRights, level);
            if (internalLevel == CTRL_LEVEL.CTRL_LEVEL_INVALID)
                return null;

            // try to find a suitable invitation
            var user = OperationContext.Current.ServiceSecurityContext.WindowsIdentity.User;
            foreach (var existingData in InvitationData.Snapshot)
            {
                // check if the user, permissions and control level match
                if (existingData.User == user && existingData.SessionRights == sessionRights && existingData.InitialControlLevel == internalLevel)
                {
                    // lock the data
                    lock (existingData)
                    {
                        // skip this invitation if it's already assigned
                        if (existingData.AttendeeRemoteName != null)
                            continue;

                        // initalize the data and return the stream
                        existingData.Invitation.Revoked = false;
                        existingData.AttendeeRemoteName = CreateAttendeeName();
                        return FinalizeResponse(existingData);
                    }
                }
            }

            // no matching invitation found, create a new one and return the response
            var newData = new InvitationData()
            {
                User = user,
                SessionRights = sessionRights,
                InitialControlLevel = internalLevel,
                AttendeeRemoteName = CreateAttendeeName(),
            };
            lock (newData)
            {
                newData.CreateInvitation(session, null, "", 1);
                return FinalizeResponse(newData);
            }
        }
    }
}

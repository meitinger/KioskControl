/* Copyright (C) 2014-2016, Manuel Meitinger
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
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Web;
using System.Text;
using System.Threading;
using RDPCOMAPILib;

namespace Aufbauwerk.Tools.KioskControl
{
    [DataContract]
    public class Connection
    {
        [DataMember]
        public string DomainName { get; set; }

        [DataMember]
        public string UserName { get; set; }

        [DataMember]
        public string MachineName { get; set; }

        [DataMember]
        public string ConnectionString { get; set; }

        [DataMember]
        public string AttendeeName { get; set; }
    }

    [ServiceContract]
    public interface IContract
    {
        [WebGet(UriTemplate = "/")]
        [OperationContract]
        Stream HtmlViewer();

        [WebGet(UriTemplate = "/View")]
        [OperationContract]
        Stream View();

        [WebGet(UriTemplate = "/Interact")]
        [OperationContract]
        Stream Interact();

        [WebGet(UriTemplate = "/Connect", ResponseFormat = WebMessageFormat.Json)]
        [OperationContract]
        Connection Connect();

        [WebGet(UriTemplate = "/ConnectToClient?ConnectionString={connectionString}", ResponseFormat = WebMessageFormat.Json)]
        [OperationContract]
        void ConnectToClient(string connectionString);

        [WebGet(UriTemplate = "/CreateVirtualChannel?ChannelName={channelName}", ResponseFormat = WebMessageFormat.Json)]
        [OperationContract]
        void CreateVirtualChannel(string channelName);
    }

    public class CorsSupportAttribute : Attribute, IServiceBehavior
    {
        class Inspector : IDispatchMessageInspector
        {
            public readonly static Inspector Instance = new Inspector();

            Inspector() { }

            public object AfterReceiveRequest(ref Message request, IClientChannel channel, InstanceContext instanceContext)
            {
                return request.Properties["httpRequest"];
            }

            public void BeforeSendReply(ref Message reply, object correlationState)
            {
                var origin = ((HttpRequestMessageProperty)correlationState).Headers["Origin"];
                var headers = ((HttpResponseMessageProperty)reply.Properties["httpResponse"]).Headers;
                headers["Access-Control-Allow-Origin"] = origin ?? "*";
                headers["Access-Control-Allow-Credentials"] = "true";
            }
        }

        public void AddBindingParameters(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase, System.Collections.ObjectModel.Collection<ServiceEndpoint> endpoints, System.ServiceModel.Channels.BindingParameterCollection bindingParameters) { }
        public void Validate(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase) { }

        public void ApplyDispatchBehavior(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase)
        {
            foreach (ChannelDispatcher channelDispatcher in serviceHostBase.ChannelDispatchers)
                foreach (EndpointDispatcher endpointDispatcher in channelDispatcher.Endpoints)
                    endpointDispatcher.DispatchRuntime.MessageInspectors.Add(Inspector.Instance);
        }
    }

    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, ConcurrencyMode = ConcurrencyMode.Multiple)]
    [CorsSupport]
    public class Service : IContract
    {
        class UserData
        {
            class PendingConnection
            {
                public Timer TimeoutTimer { get; set; }
                public CTRL_LEVEL InitialControlLevel { get; set; }
            }

            readonly static object dataLock = new object();
            readonly static Dictionary<string, UserData> byConnectionString = new Dictionary<string, UserData>();
            readonly static Dictionary<SecurityIdentifier, UserData> bySid = new Dictionary<SecurityIdentifier, UserData>();
            readonly static HashSet<string> issuedAttendeeNames = new HashSet<string>();
            readonly static RandomNumberGenerator rng = RandomNumberGenerator.Create();

            public static UserData FromAttendee(IRDPSRAPIAttendee attendee)
            {
                if (attendee == null)
                    throw new ArgumentNullException("attendee");

                // get the attendee's invitation
                var invitation = attendee.Invitation;
                try
                {
                    // find the user data that corresponds to the given connection string
                    UserData data;
                    lock (dataLock)
                        if (!byConnectionString.TryGetValue(invitation.ConnectionString, out data))
                            return null;

                    // remove a pending connection or ensure the attendee is connected
                    PendingConnection pendingConnection;
                    lock (data.connectionLock)
                    {
                        if (!data.pendingConnections.TryGetValue(attendee.RemoteName, out pendingConnection))
                            return data.connectedAttendeeIds.Contains(attendee.Id) ? data : null;
                        data.pendingConnections.Remove(attendee.RemoteName);
                        data.connectedAttendeeIds.Add(attendee.Id);
                    }
                    pendingConnection.TimeoutTimer.Dispose();

                    // set the initial control level
                    if (pendingConnection.InitialControlLevel != CTRL_LEVEL.CTRL_LEVEL_INVALID)
                        attendee.ControlLevel = pendingConnection.InitialControlLevel;

                    // enable all virtual channels
                    IRDPSRAPIVirtualChannel[] channels;
                    lock (data.grantedVirtualChannels)
                    {
                        channels = new IRDPSRAPIVirtualChannel[data.grantedVirtualChannels.Values.Count];
                        data.grantedVirtualChannels.Values.CopyTo(channels, 0);
                    }
                    foreach (var channel in channels)
                    {
                        try { channel.SetAccess(attendee.Id, CHANNEL_ACCESS_ENUM.CHANNEL_ACCESS_ENUM_SENDRECEIVE); }
                        catch { }
                    }

                    // return the data
                    return data;
                }
                finally { Marshal.ReleaseComObject(invitation); }
            }

            public static UserData FromContext(RDPSession session)
            {
                if (session == null)
                    throw new ArgumentNullException("session");

                // get the current identity and effective permissions
                var identity = OperationContext.Current.ServiceSecurityContext.WindowsIdentity;
                var effectivePermissions = Security.GetEffectivePermissions(identity.Token);
                var sid = identity.User;
                lock (dataLock)
                {
                    // try to get an existing user data object
                    UserData data;
                    if (!bySid.TryGetValue(sid, out data))
                    {
                        // create the invitation and user data
                        var inviationManager = session.Invitations;
                        try
                        {
                            var invitation = inviationManager.CreateInvitation(null, effectivePermissions.ToString(), "", 0);
                            try { data = new UserData(invitation.ConnectionString, effectivePermissions); }
                            finally { Marshal.ReleaseComObject(invitation); }
                        }
                        finally { Marshal.ReleaseComObject(inviationManager); }

                        // add it to the dictionaries
                        byConnectionString.Add(data.ConnectionString, data);
                        bySid.Add(sid, data);
                    }
                    else
                        // update the user's effective permissions
                        data.EffectivePermissions = effectivePermissions;
                    return data;
                }
            }

            readonly object connectionLock = new object();
            readonly Dictionary<string, PendingConnection> pendingConnections = new Dictionary<string, PendingConnection>();
            readonly HashSet<int> connectedAttendeeIds = new HashSet<int>();
            readonly Dictionary<string, IRDPSRAPIVirtualChannel> grantedVirtualChannels = new Dictionary<string, IRDPSRAPIVirtualChannel>();

            UserData(string connectionString, SessionRights effectivePermissions)
            {
                ConnectionString = connectionString;
                EffectivePermissions = effectivePermissions;
            }

            void ConnectionTimeout(object attendeeName)
            {
                // remove the pending connection if it still exists
                PendingConnection pendingConnection;
                lock (connectionLock)
                {
                    if (!pendingConnections.TryGetValue((string)attendeeName, out pendingConnection))
                        return;
                    pendingConnections.Remove((string)attendeeName);
                }
                pendingConnection.TimeoutTimer.Dispose();
            }

            public string ConnectionString
            {
                get;
                private set;
            }

            public SessionRights EffectivePermissions
            {
                get;
                private set;
            }

            public void GrantChannelAccess(IRDPSRAPIVirtualChannel channel)
            {
                if (channel == null)
                    throw new ArgumentNullException("channel");

                lock (grantedVirtualChannels)
                {
                    // do nothing if already granted
                    if (grantedVirtualChannels.ContainsKey(channel.Name))
                    {
                        Marshal.ReleaseComObject(channel);
                        return;
                    }

                    // add the channel
                    grantedVirtualChannels.Add(channel.Name, channel);
                }

                // grant channel access to all established connections (best effort)
                int[] attendeeIds;
                lock (connectionLock)
                {
                    attendeeIds = new int[connectedAttendeeIds.Count];
                    connectedAttendeeIds.CopyTo(attendeeIds, 0);
                }
                foreach (var attendeeId in attendeeIds)
                {
                    try { channel.SetAccess(attendeeId, CHANNEL_ACCESS_ENUM.CHANNEL_ACCESS_ENUM_SENDRECEIVE); }
                    catch { }
                }
            }

            public string CreateAttendee(RDPSession session, CTRL_LEVEL initialControlLevel = CTRL_LEVEL.CTRL_LEVEL_INVALID)
            {
                if (session == null)
                    throw new ArgumentNullException("session");

                // create a strong random hex string including the user name
                var userName = OperationContext.Current.ServiceSecurityContext.WindowsIdentity.Name;
                var buffer = new byte[64];
                var builder = new StringBuilder(userName.Length + buffer.Length * 2 + 2);
            TryAgain:
                rng.GetBytes(buffer);
                builder.Length = 0;
                if (userName.IndexOf('\\') == -1)
                    builder.Append('\\');
                builder.Append(userName);
                builder.Append('\\');
                for (int i = 0; i < buffer.Length; i++)
                    builder.Append(buffer[i].ToString("X2", CultureInfo.InvariantCulture));
                var attendeeName = builder.ToString();

                // make sure it doesn't exist
                lock (issuedAttendeeNames)
                {
                    if (issuedAttendeeNames.Contains(attendeeName))
                        goto TryAgain;
                    issuedAttendeeNames.Add(attendeeName);
                }

                // create a new pending connection and return the attendee name
                lock (connectionLock)
                {
                    pendingConnections.Add(attendeeName, new PendingConnection()
                    {
                        TimeoutTimer = new Timer(ConnectionTimeout, attendeeName, Properties.Settings.Default.ConnectionTimeout, TimeSpan.Zero),
                        InitialControlLevel = initialControlLevel,
                    });
                }
                return attendeeName;
            }

            public bool DestroyAttendee(IRDPSRAPIAttendee attendee)
            {
                if (attendee == null)
                    throw new ArgumentNullException("attendee");

                // either remove a pending or established connction
                PendingConnection pendingConnection;
                lock (connectionLock)
                {
                    if (!pendingConnections.TryGetValue(attendee.RemoteName, out pendingConnection))
                        return connectedAttendeeIds.Remove(attendee.Id);
                    pendingConnections.Remove(attendee.RemoteName);
                }
                pendingConnection.TimeoutTimer.Dispose();
                return true;
            }
        }

        readonly RDPSession session;

        public Service(RDPSession session)
        {
            if (session == null)
                throw new ArgumentNullException("session");

            // store the session
            this.session = session;

            // hook the session events
            session.OnAttendeeConnected += OnAttendeeConnected;
            session.OnControlLevelChangeRequest += OnControlLevelChangeRequest;
            session.OnAttendeeDisconnected += OnAttendeeDisconnected;
        }

        void OnAttendeeConnected(object pAttendee)
        {
            var attendee = (IRDPSRAPIAttendee)pAttendee;
            try
            {
                // get the user data
                var data = UserData.FromAttendee(attendee);

                // terminate connections of unknown attendees
                if (data == null)
                    attendee.TerminateConnection();
            }
            finally { Marshal.ReleaseComObject(attendee); }
        }

        void OnControlLevelChangeRequest(object pAttendee, CTRL_LEVEL RequestedLevel)
        {
            var attendee = (IRDPSRAPIAttendee)pAttendee;
            try
            {
                // get the user data and check the known control levels
                var data = UserData.FromAttendee(attendee);
                if (data != null)
                {
                    switch (RequestedLevel)
                    {
                        case CTRL_LEVEL.CTRL_LEVEL_NONE:
                            if ((data.EffectivePermissions & SessionRights.Connect) == 0)
                                return;
                            break;
                        case CTRL_LEVEL.CTRL_LEVEL_VIEW:
                            if ((data.EffectivePermissions & SessionRights.View) == 0)
                                return;
                            break;
                        case CTRL_LEVEL.CTRL_LEVEL_INTERACTIVE:
                            if ((data.EffectivePermissions & SessionRights.Interact) == 0)
                                return;
                            break;
                        default:
                            return;
                    }

                    // set the requested control level
                    attendee.ControlLevel = RequestedLevel;
                }
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
                    // get the user data and destroy the current attendee
                    var data = UserData.FromAttendee(attendee);
                    if (data != null)
                        data.DestroyAttendee(attendee);
                }
                finally { Marshal.ReleaseComObject(attendee); }
            }
            finally { Marshal.ReleaseComObject(info); }
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

        void DisableCaching()
        {
            // restrict caching in the response headers
            WebOperationContext.Current.OutgoingResponse.Headers[HttpResponseHeader.CacheControl] = "max-age=0, no-cache, no-store";
            WebOperationContext.Current.OutgoingResponse.Headers[HttpResponseHeader.Pragma] = "no-cache";
        }

        void DemandPermission(SessionRights rights)
        {
            // throw an access denied permission if the rights aren't granted
            if (!Security.HasPermission(OperationContext.Current.ServiceSecurityContext.WindowsIdentity.Token, rights))
            {
                WebOperationContext.Current.OutgoingResponse.StatusCode = HttpStatusCode.Forbidden;
                throw new UnauthorizedAccessException();
            }
        }

        Stream IContract.View()
        {
            // ensure view permissions and return the viewer
            DemandPermission(SessionRights.View);
            return HtmlViewer(CTRL_LEVEL.CTRL_LEVEL_VIEW);
        }

        Stream IContract.Interact()
        {
            // ensure interact permissions and return the viewer
            DemandPermission(SessionRights.Interact);
            return HtmlViewer(CTRL_LEVEL.CTRL_LEVEL_INTERACTIVE);
        }

        public Stream HtmlViewer()
        {
            // get the highest control level and return the viewer
            var permission = Security.GetEffectivePermissions(OperationContext.Current.ServiceSecurityContext.WindowsIdentity.Token);
            return HtmlViewer
            (
                (permission & SessionRights.Interact) != 0 ? CTRL_LEVEL.CTRL_LEVEL_INTERACTIVE :
                (permission & SessionRights.View) != 0 ? CTRL_LEVEL.CTRL_LEVEL_VIEW :
                (permission & SessionRights.Connect) != 0 ? CTRL_LEVEL.CTRL_LEVEL_NONE :
                CTRL_LEVEL.CTRL_LEVEL_INVALID
            );
        }

        public Stream HtmlViewer(CTRL_LEVEL controlLevel)
        {
            // ensure connect rights and return the viewer
            DemandPermission(SessionRights.Connect);
            DisableCaching();
            var data = UserData.FromContext(session);
            WebOperationContext.Current.OutgoingResponse.ContentType = "text/html; charset=UTF-8";
            return new MemoryStream
            (
                Encoding.UTF8.GetBytes
                (
                    string.Format
                    (
                         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n" +
                         "<html>\n" +
                         "  <head>\n" +
                         "    <title>{0}\\{1} @ {2}</title>\n" +
                         "    <meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"/>\n" +
                         "  </head>\n" +
                         "  <body onload=\"try{{RDPViewer.DisconnectedText=decodeURIComponent('{5}');RDPViewer.Connect(decodeURIComponent('{3}'),decodeURIComponent('{4}'),'');}}catch(e){{alert(e.message);}}\" style=\"margin:0;padding:0;\">\n" +
                         "    <object id=\"RDPViewer\" classid=\"clsid:32be5ed2-5c86-480f-a914-0ff8885a1b3f\" width=\"100%\" height=\"100%\" style=\"border:0;margin:0;padding:0;\"></object>\n" +
                         "  </body>\n" +
                         "</html>",
                         Environment.UserDomainName,
                         Environment.UserName,
                         Environment.MachineName,
                         EscapeString(data.ConnectionString),
                         EscapeString(data.CreateAttendee(session, controlLevel)),
                         EscapeString(Properties.Settings.Default.DisconnectedText)
                     )
                )
            );
        }

        public Connection Connect()
        {
            // check the permission and return the connection
            DemandPermission(SessionRights.Connect);
            DisableCaching();
            var data = UserData.FromContext(session);
            return new Connection()
            {
                DomainName = Environment.UserDomainName,
                UserName = Environment.UserName,
                MachineName = Environment.MachineName,
                ConnectionString = data.ConnectionString,
                AttendeeName = data.CreateAttendee(session),
            };
        }

        public void ConnectToClient(string connectionString)
        {
            if (connectionString == null)
            {
                WebOperationContext.Current.OutgoingResponse.StatusCode = HttpStatusCode.BadRequest;
                throw new ArgumentNullException("connectionString");
            }

            // check the permission and connect to the client
            DemandPermission(SessionRights.ConnectToClient);
            session.ConnectToClient(connectionString);
        }

        public void CreateVirtualChannel(string channelName)
        {
            if (channelName == null)
            {
                WebOperationContext.Current.OutgoingResponse.StatusCode = HttpStatusCode.BadRequest;
                throw new ArgumentNullException("connectionString");
            }

            // check the permission and get the channel manager
            DemandPermission(SessionRights.CreateVirtualChannel);
            var manager = session.VirtualChannelManager;
            try
            {
                // get or create the channel
                IRDPSRAPIVirtualChannel channel;
                try { channel = manager[channelName]; }
                catch { channel = manager.CreateVirtualChannel(channelName, CHANNEL_PRIORITY.CHANNEL_PRIORITY_MED, 0); }

                // grant access to the client
                UserData.FromContext(session).GrantChannelAccess(channel);
            }
            finally { Marshal.ReleaseComObject(manager); }
        }
    }
}

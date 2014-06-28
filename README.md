Kiosk Control
=============


Description
-----------
This program allows you to view or control a kiosk terminal in a secure, fast
and native way using Internet Explorer.
The term *kiosk terminal* in this case refers to a machine running Windows with
an auto-logon user configuration, or any other scenario where you want to view
or control the active console session, much like *Windows Remote Assistance*
but without any necessary user interaction to grant access, which instead is
governed by ACLs.

Usage
-----
Simply register the application to auto-run when the user logs on. This can be
done in various ways and is outside the scope of this readme.
To connect, start Internet Explorer on the client and navigate to the URL
specified in the config file, which is described in the following section.

Note: Append `view` or `interact` after the base address to specify the control
level. If nothing is appended, the highest granted level is used.

Configuration
-------------
The following settings can be configured in the `KioskControl.exe.config` file:
- *Security*: A SDDL string that stores the access control list for the kiosk
  session. This setting can also be edited by running the program with the
  `/editsecurity` switch, which displays the familiar Windows security dialog.
- *ConnectionTimeout*: The amount of time a client has before its token becomes
  invalid.
- *DisconnectText*: The message that is displayed if the connection gets lost.

The *Windows Communication Framework* configuration is also stored within this
file. This part specified how the client authenticates (either `Ntlm` or
`Windows` is required - use the former if the user is logged on with a guest
account) and where it should listen for incoming connections. (Remember to
[register](http://msdn.microsoft.com/en-us/library/ms733768(v=vs.90).aspx) the
namespace and to poke the necessary holes into the firewall.)

Requirements
------------
Since the program relies on the Windows Desktop Sharing API, at least Windows
Vista or higher is required, on the kiosk terminal as well as on the client.

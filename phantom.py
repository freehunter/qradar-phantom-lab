import socket
import logging
import random
import time
import syslog

#This is where we set our target server and ports
#UDP_IP = "192.168.1.196"
UDP_IP = "10.16.20.200"
UDP_PORT = 514
while True:
   #We're going to read from a list of usernames
   username = random.choice(list(open('usernames.txt'))).rstrip()

   #We're going to read from a list of hostnames and IP addresses
   windows_src = random.choice(list(open('windows.txt'))).rstrip()
   winhostname = windows_src.split(",")[0]
   winsrc = windows_src.split(",")[1]
   
   windows_dst = random.choice(list(open('windows.txt'))).rstrip()
   windst = windows_dst.split(",")[1]
   windst_host = windows_dst.split(",")[0]
   
   #Same for hostnames
   #winhostname = random.choice(list(open('win-hostnames.txt'))).rstrip()

   #and ports
   srcprt = random.choice(list(open('prt.txt'))).rstrip()
   dstprt = random.choice(list(open('prt.txt'))).rstrip()

   #Pick randomly between log source types to send
   #Bluecoat
   #Palo Alto
   #Windows
   #Linux
   #BIND DNS
   choice = [1,2,3,4,5,6,7,8,9,10,11,12]
   #choice = [12]
   msg = random.choice(choice)

   #send our logs
   #Bluecoat messages
   if msg < 4:
      host_choice = random.choice([1, 2])
      print(host_choice)
      if host_choice == 1:
         src_address = random.choice(list(open('linux.txt'))).rstrip()
      elif host_choice == 2:
         src_address = random.choice(list(open('windows.txt'))).rstrip()
         hostname = src_address.split(",")[0]
      src =  src_address.split(",")[1]
      
      host_choice = random.choice([1, 2])
      if host_choice == 1:
         dst_address = random.choice(list(open('linux.txt'))).rstrip()
      elif host_choice == 2:
         dst_address = random.choice(list(open('windows.txt'))).rstrip()
      dst =  dst_address.split(",")[1]
      
      choice2 = [1,2,3,4,5,6,7,8,9]
      msg2 = random.choice(choice2)
      if msg2 <= 7:
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         palo_app = random.choice(list(open('pa_apps.txt'))).rstrip()
         url = palo_app.split(",")[1]
         ext = random.choice(list(open('ext_ip.txt'))).rstrip()
         ext_ip =  ext.split(",")[1]
         webprt = random.choice(list(open('web_ports.txt'))).rstrip()
         bluecoat = random.choice(list(open('bluecoat.txt'))).rstrip()
         bc_action = bluecoat.split(",")[0]
         bc_status = bluecoat.split(",")[1]
         bc_method = bluecoat.split(",")[2]
         bc_result = bluecoat.split(",")[3]
         ua = random.choice(list(open('user_agent.txt'))).rstrip()
         MESSAGE = 'Bluecoat|src={src}|srcport={srcprt}|dst={ext_ip}|dstport={webprt}|username={username}|devicetime={datestamp2} GMT]|s-action={bc_action}|sc-status={bc_status}|cs-method={bc_method}|time-taken=1|sc-bytes=185|cs-bytes=216|cs-uri-scheme=tcp|cs-host={url}|cs-uri-path=/|cs-uri-query=-|cs-uri-extension=-|cs-auth-group=SIOC\Internet|rs(Content-Type)=-|cs(User-Agent)={ua}|cs(Referer)=-|sc-filter-result={bc_result}|filter-category=Technology/Internet|cs-uri=tcp://{url}:443'.format(username=username, srcprt=srcprt, ext_ip=ext_ip, datestamp2=datestamp2, url=url, src=src, webprt=webprt, bc_action=bc_action, bc_status=bc_status, bc_method=bc_method, bc_result=bc_result, ua=ua)
      elif msg2 == 8:
         datestamp = time.strftime("%b %d %H:%M:%S")
         MESSAGE = '<29>{datestamp} ProxySG: 250017 Authentication failed from {src}: user {username} (realm SIOC)(0) NORMAL_EVENT authutility.cpp 113'.format(src=src, username=username, datestamp=datestamp)
      elif msg2 == 9:
         datestamp = time.strftime("%b %d %H:%M:%S")
         MESSAGE = '<29>{datestamp} ProxySG: 250047 Administrator login, user \'admin\', from {src}(0) NORMAL_EVENT authconsole.cpp 487'.format(src=src, username=username, datestamp=datestamp)
   #Palo Alto
   elif msg == 4:
      #We're going to read from a list of hostnames and IP addresses
      host_choice = random.choice([1, 2, 3])
      if host_choice == 1:
         src_address = random.choice(list(open('linux.txt'))).rstrip()
      elif host_choice == 2:
         src_address = random.choice(list(open('windows.txt'))).rstrip()
      elif host_choice == 3:
         src_address = random.choice(list(open('ext_ip.txt'))).rstrip()
      hostname = src_address.split(",")[0]
      palo = random.choice(list(open('palo.txt'))).rstrip()
      palo_ip = palo.split(",")[1]
      palo_host = palo.split(",")[0]
      src = src_address.split(",")[1]
      
      palo_app = random.choice(list(open('pa_apps.txt'))).rstrip()
      app = palo_app.split(",")[0]
      misc = palo_app.split(",")[1]
      cat = palo_app.split(",")[2]


      ext = random.choice(list(open('ext_ip.txt'))).rstrip()
      ext_ip = ext.split(",")[1]

      dst_address = random.choice(list(open('palo.txt'))).rstrip()
      dst = dst_address.split(",")[1]
      
      pa = random.choice(list(open('pa_cat.txt'))).rstrip()
      pa_action = pa.split(",")[0]
      pa_cat = pa.split(",")[1]
      pa_sub = pa.split(",")[2]
      pa_reason = pa.split(",")[3]
      
      choice2 = [1,2,3,4,5,6,7,8,9,10,11,12,13,14]
      msg2 = random.choice(choice2) 
      if msg2 == 1:
         datestamp = time.strftime("%b %d %H:%M:%S")
         datestamp3 = time.strftime("%b %d %Y %H:%M:%S")
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         ips = random.choice(list(open('pa_ips_cat.txt'))).rstrip()
         ips_threat = ips.split(",")[0]
         ips_cat = ips.split(",")[1]
         ips_sub = ips.split(",")[2]
         ips_action = ips.split(",")[3]
         MESSAGE = '<14>{datestamp} {palo_host} LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|7.1.14|{ips_threat}|ReceiveTime={datestamp2}|SerialNumber=001122334455|cat={ips_cat}|subtype={ips_sub}|devTime={datestamp3} GMT|src={src}|dst={ext_ip}|srcPostNAT=0.0.0.0|dstPostNAT=0.0.0.0|RuleName=Server with internet access|usrName=|SourceUser=|DestinationUser=|Application={app}|VirtualSystem=vsys1|SourceZone=Servers|DestinationZone=Interconnect|IngressInterface=ae1.20|EgressInterface=ethernet1/3.10|LogForwardingProfile=PA_Syslog_Trafic|SessionID=396225|RepeatCount=1|srcPort={srcprt}|dstPort=443|srcPostNATPort=0|dstPostNATPort=0|Flags=0xf000|proto=tcp|action={ips_action}|Miscellaneous="{misc}"|ThreatID=(9999)|URLCategory={cat}|sev=1|Severity=informational|Direction=client-to-server|sequence=22946006|ActionFlags=0x0|SourceLocation=10.0.0.0-10.255.255.255|DestinationLocation=US|ContentType=|PCAP_ID=0|FileDigest=|Cloud=|URLIndex=0|UserAgent=|FileType=|identSrc=|Referer=|Sender=|Subject=|Recipient=|ReportID=0|DeviceGroupHierarchyL1=0|DeviceGroupHierarchyL2=0|DeviceGroupHierarchyL3=0|DeviceGroupHierarchyL4=0|vSrcName=|DeviceName={palo_host}'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, palo_ip=palo_ip, datestamp=datestamp, palo_host=palo_host, ext_ip=ext_ip, dst=dst, datestamp2=datestamp2, app=app, misc=misc, cat=cat, datestamp3=datestamp3, ips_threat=ips_threat, ips_cat=ips_cat, ips_sub=ips_sub, ips_action=ips_action)
      elif msg2 >= 2 and msg2 <=5:
      #internal destination
         datestamp = time.strftime("%b %d %H:%M:%S")
         datestamp3 = time.strftime("%b %d %Y %H:%M:%S")
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         MESSAGE = '<14>{datestamp} {palo_host} LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|7.1.14|{pa_action}|cat={pa_cat}|ReceiveTime={datestamp2}|SerialNumber=001122334455|Type={pa_cat}|subtype={pa_sub}|devTime={datestamp3} GMT|src={src}|dst={dst}|srcPostNAT=0.0.0.0|dstPostNAT=0.0.0.0|RuleName=All_to_Servers|usrName=SIOC\{username}|SourceUser=SIOC\{username}|DestinationUser=|Application={app}|VirtualSystem=vsys1|SourceZone=Users|DestinationZone=Servers|IngressInterface=ae1.40|EgressInterface=ae1.20|LogForwardingProfile=SIOC_Alerts|SessionID=312844|RepeatCount=1|srcPort={srcprt}|dstPort={dstprt}|srcPostNATPort=0|dstPostNATPort=0|Flags=0x4000|proto=tcp|action={pa_action}|totalBytes=2871|dstBytes=70|srcBytes=2801|totalPackets=5|StartTime={datestamp2}|ElapsedTime=0|URLCategory={cat}|sequence=241584115|ActionFlags=0x0|SourceLocation=10.0.0.0-10.255.255.255|DestinationLocation=10.0.0.0-10.255.255.255|dstPackets=1|srcPackets=4|SessionEndReason={pa_reason}|DeviceGroupHierarchyL1=0|DeviceGroupHierarchyL2=0|DeviceGroupHierarchyL3=0|DeviceGroupHierarchyL4=0|vSrcName=|DeviceName=PA-3050_HA1|ActionSource=from-policy'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, palo_ip=palo_ip, datestamp=datestamp, palo_host=palo_host, ext_ip=ext_ip, dst=dst, datestamp2=datestamp2, app=app, misc=misc, cat=cat, datestamp3=datestamp3, pa_action=pa_action, pa_cat=pa_cat, pa_sub=pa_sub, username=username, pa_reason=pa_reason)
      elif msg2 >=6 and msg2 <= 10:
      #external destination
         datestamp = time.strftime("%b %d %H:%M:%S")
         datestamp3 = time.strftime("%b %d %Y %H:%M:%S")
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         MESSAGE = '<14>{datestamp} {palo_host} LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|7.1.14|{pa_action}|cat={pa_cat}|ReceiveTime={datestamp2}|SerialNumber=001122334455|Type={pa_cat}|subtype={pa_sub}|devTime={datestamp3} GMT|src={src}|dst={ext_ip}|srcPostNAT=0.0.0.0|dstPostNAT=0.0.0.0|RuleName=External|usrName=SIOC\{username}|SourceUser=SIOC\{username}|DestinationUser=|Application={app}|VirtualSystem=vsys1|SourceZone=Users|DestinationZone=External|IngressInterface=ae1.40|EgressInterface=ae1.20|LogForwardingProfile=SIOC_Alerts|SessionID=312844|RepeatCount=1|srcPort={srcprt}|dstPort={dstprt}|srcPostNATPort=0|dstPostNATPort=0|Flags=0x4000|proto=tcp|action={pa_action}|totalBytes=2871|dstBytes=70|srcBytes=2801|totalPackets=5|StartTime={datestamp2}|ElapsedTime=0|URLCategory={cat}|sequence=241584115|ActionFlags=0x0|SourceLocation=10.0.0.0-10.255.255.255|DestinationLocation=10.0.0.0-10.255.255.255|dstPackets=1|srcPackets=4|SessionEndReason=n/a|DeviceGroupHierarchyL1=0|DeviceGroupHierarchyL2=0|DeviceGroupHierarchyL3=0|DeviceGroupHierarchyL4=0|vSrcName=|DeviceName=PA-3050_HA1|ActionSource=from-policy'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, palo_ip=palo_ip, datestamp=datestamp, palo_host=palo_host, ext_ip=ext_ip, dst=dst, datestamp2=datestamp2, app=app, misc=misc, cat=cat, datestamp3=datestamp3, pa_action=pa_action, pa_cat=pa_cat, pa_sub=pa_sub, username=username)
      elif msg2 == 11:
         datestamp = time.strftime("%b %d %H:%M:%S")
         datestamp3 = time.strftime("%b %d %Y %H:%M:%S")
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         pa_admin = random.choice(list(open('pa_admin.txt'))).rstrip()
         MESSAGE = '<14>{datestamp} {palo_host} 1,{datestamp2},007257000030054,SYSTEM,general,0,{datestamp2},,general,,0,0,general,informational,"{pa_admin} {src}",1210774,0x0,0,0,0,0,,{palo_host}'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, palo_ip=palo_ip, datestamp=datestamp, palo_host=palo_host, ext_ip=ext_ip, dst=dst, datestamp2=datestamp2, app=app, misc=misc, cat=cat, datestamp3=datestamp3, pa_admin=pa_admin)
      elif msg2 == 12:
         datestamp = time.strftime("%b %d %H:%M:%S")
         datestamp3 = time.strftime("%b %d %Y %H:%M:%S")
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         MESSAGE = '<14>{datestamp} {palo_host} LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|7.1.14|globalprotectgateway-auth-fail| ReceiveTime={datestamp2}|SerialNumber=001122334455|cat=SYSTEM|subtype=globalprotect|devTime={datestamp3} GMT|VirtualSystem=|Filename=GP-SSLVPN_Gateway2-N|Module=general|sev=1|Severity=informational|msg="GlobalProtect gateway user authentication failed. Login from: {src}, User name: {username}, Client OS version: Microsoft Windows 10 Pro , 64-bit, Reason: Authentication failed: User Authentication Failed, Auth type: profile."|sequence=82150|ActionFlags=0x0|DeviceGroupHierarchyL1=0|DeviceGroupHierarchyL2=0|DeviceGroupHierarchyL3=0|DeviceGroupHierarchyL4=0|vSrcName=|DeviceName={palo_host}'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, palo_ip=palo_ip, datestamp=datestamp, palo_host=palo_host, ext_ip=ext_ip, dst=dst, datestamp2=datestamp2, app=app, misc=misc, cat=cat, datestamp3=datestamp3, username=username)
      elif msg2 == 13:
         datestamp = time.strftime("%b %d %H:%M:%S")
         datestamp3 = time.strftime("%b %d %Y %H:%M:%S")
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         MESSAGE = '<14>{datestamp} {palo_host} LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|7.1.14|globalprotectgateway-logout-succ| ReceiveTime={datestamp2}|SerialNumber=001122334455|cat=SYSTEM|subtype=globalprotect|devTime=Apr 12 2018 16:28:22 GMT|VirtualSystem=|Filename=GP-SSLVPN_Gateway2-N|Module=general|sev=1|Severity=informational|msg="GlobalProtect gateway user logout succeeded. User name: {username}, Client OS version: Microsoft Windows 10 Pro , 64-bit, Reason: user session expired."|sequence=84466|ActionFlags=0x0|DeviceGroupHierarchyL1=0|DeviceGroupHierarchyL2=0|DeviceGroupHierarchyL3=0|DeviceGroupHierarchyL4=0|vSrcName=|DeviceName={palo_host}'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, palo_ip=palo_ip, datestamp=datestamp, palo_host=palo_host, ext_ip=ext_ip, dst=dst, datestamp2=datestamp2, app=app, misc=misc, cat=cat, datestamp3=datestamp3, username=username)
      elif msg2 == 14:
         datestamp = time.strftime("%b %d %H:%M:%S")
         datestamp3 = time.strftime("%b %d %Y %H:%M:%S")
         datestamp2 = time.strftime("%Y/%m/%d %H:%M:%S")
         MESSAGE = '<14>{datestamp} {palo_host} LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|7.1.14|general| ReceiveTime={datestamp2}|SerialNumber=001122334455|cat=SYSTEM|subtype=general|devTime={datestamp3} GMT|VirtualSystem=|Filename=|Module=general|sev=1|Severity=informational|msg="User "{username} logged in via Web from {src} using https"|sequence=84438|ActionFlags=0x0|DeviceGroupHierarchyL1=0|DeviceGroupHierarchyL2=0|DeviceGroupHierarchyL3=0|DeviceGroupHierarchyL4=0|vSrcName=|DeviceName={palo_host}'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, palo_ip=palo_ip, datestamp=datestamp, palo_host=palo_host, ext_ip=ext_ip, dst=dst, datestamp2=datestamp2, app=app, misc=misc, cat=cat, datestamp3=datestamp3, username=username)
   elif msg >= 5 and msg <=9: #Windows machines
      datestamp = time.strftime("%b %d %H:%M:%S")
      win_events = random.choice(list(open('win-events.txt'))).rstrip()
      eventid = win_events.split(",")[0]
      keywords = win_events.split(",")[1]
      task = win_events.split(",")[2]
      message = win_events.split(",")[3]
      MESSAGE = '<13>{datestamp} {winhostname} AgentDevice=WindowsLog    AgentLogFile=Security    PluginVersion=7.2.7.20    Source=Microsoft-Windows-Security-Auditing    Computer={windst_host}    OriginatingComputer={windst}    User=    Domain=    EventID={eventid}    EventIDCode={eventid}    EventType=8    EventCategory=0    RecordNumber=644124781    TimeGenerated=1523478419    TimeWritten=1523478419    Level=Log Always    Keywords={keywords}   Task={task} Opcode=Info Message={message}  Subject:  Security ID:  NULL SID  Account Name:  -  Account Domain:  -  Logon ID:  0x0  Logon Type:   3  Impersonation Level:  Impersonation  New Logon:  Security ID:  SIOC\{username}  Account Name:  {username}  Account Domain:  SIOC  Logon ID:  0xE9A64342  Logon GUID:  {{905B9F13-F6D8-8DD9-719B-933E40659F0E}}  Process Information:  Process ID:  0x0  Process Name:  -  Network Information:  Workstation Name: -  Source Network Address: {winsrc}  Source Port:  {srcprt}  Detailed Authentication Information:  Logon Process:  Kerberos  Authentication Package'.format(winsrc=winsrc,windst=windst,winhostname=winhostname,srcprt=srcprt,username=username, windst_host=windst_host, datestamp=datestamp, eventid=eventid, keywords=keywords, task=task, message=message)
   elif msg == 10: #Linux machines
      #We're going to read from a list of hostnames and IP addresses
      src_address = random.choice(list(open('linux.txt'))).rstrip()
      hostname = src_address.split(",")[0]
      src = src_address.split(",")[1]

      dst_address = random.choice(list(open('linux.txt'))).rstrip()
      dst = dst_address.split(",")[1]
      
      choice2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
      msg2 = random.choice(choice2)
      if msg2 >= 1 and msg2 <= 3:
         MESSAGE = '<14>1 2018-04-10T17:40:13.308962-04:00 {hostname} sshd[5279]: Connection from {src} port {dstprt} on {src} port 22'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt)
      elif msg2 >= 2 and msg2 <= 4:
         datestamp = time.strftime("%b %d %H:%M:%S")
         MESSAGE = '<86>{datestamp} {hostname} sshd[34325]: Connection closed by {dst} [preauth]'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, dst=dst, datestamp=datestamp) 
      elif msg2 == 5:
         datestamp = time.strftime("%b %d %H:%M:%S")
         linux_msg = random.choice(list(open('linux_msg.txt'))).rstrip()
         MESSAGE = '<86>{datestamp} {hostname} sshd[4328]: {linux_msg} for {username} from {src} port {dstprt} ssh2'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, datestamp=datestamp, username=username, linux_msg=linux_msg)
      elif msg2 == 6:
         datestamp = time.strftime("%b %d %H:%M:%S")
         MESSAGE = '<85>{datestamp} {hostname} passwd: pam_unix(passwd:chauthtok): password changed for {username}'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, dst=dst, datestamp=datestamp, username=username)
      elif msg2 >= 7 and msg2 <= 10:
         datestamp = time.strftime("%Y-%m-%dT%H:%M:%S000000-")
         MESSAGE = '<14>1 {datestamp}04:00 {hostname} sshd[5837]: Accepted publickey for {username} from {src} port {srcprt} ssh2: RSA 2a:50:1b:8b:93:7c:28:0a:d4:70:00:eb:03:d1:b2:14:cb:f5:db:ec'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt, dst=dst, datestamp=datestamp, username=username)

   elif msg == 11: #BIND DNS
      #We're going to read from a list of hostnames and IP addresses
      host_choice = random.choice([1, 2])
      if host_choice == 1:
         src_address = random.choice(list(open('linux.txt'))).rstrip()
      elif host_choice == 2:
         src_address = random.choice(list(open('windows.txt'))).rstrip()
      hostname = src_address.split(",")[0]
      
      host_choice2 = random.choice([1, 2, 3])
      if host_choice2 == 1:
         src_address2 = random.choice(list(open('linux.txt'))).rstrip()
      elif host_choice2 == 2:
         src_address2 = random.choice(list(open('windows.txt'))).rstrip()
      elif host_choice2 == 3:
         src_address2 = random.choice(list(open('ext_ip.txt'))).rstrip()
      ext_ip = src_address2.split(",")[1]
      ext_host = src_address2.split(",")[0]

      dst_address = random.choice(list(open('linux.txt'))).rstrip()
      dst = dst_address.split(",")[1]
      
      choice2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
      msg2 = random.choice(choice2)
      datestamp = time.strftime("%b %d %H:%M:%S")
      datestamp2 = time.strftime("%d-%b-%Y %H:%M:%S")
      MESSAGE='<86>{datestamp} dns1 named[5514]: {datestamp2}.223 queries: info: client {src}#{srcprt} ({ext_host}.local): query: {ext_host} IN A + {ext_ip}'.format(datestamp=datestamp, src=src, srcprt=srcprt, datestamp2=datestamp2, hostname=hostname, ext_ip=ext_ip, ext_host=ext_host)
   
   elif msg == 12: #Symantec Endpoint Protection
     #We're going to read from a list of hostnames and IP addresses
     host_choice = random.choice([1, 2])
     if host_choice == 1:
       src_address = random.choice(list(open('linux.txt'))).rstrip()
     elif host_choice == 2:
       src_address = random.choice(list(open('windows.txt'))).rstrip()
     src = src_address.split(",")[1]
     hostname = src_address.split(",")[0]
  
     host_choice2 = random.choice([1, 2, 3])
     if host_choice2 == 1:
       src_address2 = random.choice(list(open('linux.txt'))).rstrip()
     elif host_choice2 == 2:
       src_address2 = random.choice(list(open('windows.txt'))).rstrip()
     elif host_choice2 == 3:
       src_address2 = random.choice(list(open('ext_ip.txt'))).rstrip()
     ext_ip = src_address2.split(",")[1]
     ext_host = src_address2.split(",")[0]
  
     sep_stuff1 = random.choice(list(open('sym_risk.txt'))).rstrip()
     category = sep_stuff1.split(",")[0]
     risk = sep_stuff1.split(",")[1]
     misc = sep_stuff1.split(",")[2]
     sep_set = sep_stuff1.split(",")[3]
     sep_type = sep_stuff1.split(",")[4]
     sep_stuff2 = random.choice(list(open('sym_action.txt'))).rstrip()
     sep_aa = sep_stuff2.split(",")[0]
     sep_ra = sep_stuff2.split(",")[1]
     sep_sa = sep_stuff2.split(",")[2]

     dst_address = random.choice(list(open('linux.txt'))).rstrip()
     dst = dst_address.split(",")[1]
  
     choice2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
     msg2 = random.choice(choice2)
     datestamp = time.strftime("%b %d %H:%M:%S")
     datestamp2 = time.strftime("%Y-%b-%d %H:%M:%S")
     MESSAGE='<54>Apr 13 13:46:42 SEP1 SymantecServer: {category},IP Address: {src},Computer name: {hostname},Intensive Protection Level: 0,Certificate issuer: ,Certificate signer: ,Certificate thumbprint: ,Signing timestamp: 0,Certificate serial number: ,Source: Auto-Protect scan,Risk name: {risk},Occurrences: 1,{misc},,Actual action: {sep_aa},Requested action: {sep_ra},Secondary action: {sep_sa},Event time: {datestamp2},Inserted: {datestamp2},End: {datestamp2},Last update time: {datestamp2},Domain: SIOC,Group: My Company\Test,Server: SEP1,User: {username},Source computer: ,Source IP: ,Disposition: Good,Download site: ,Web domain: ,Downloaded by: iexplore.exe,Prevalence: This file has been seen by millions of Symantec users.,Confidence: This file is trustworthy.,URL Tracking Status: Off,,First Seen: Symantec has known about this file for more than 1 year.,Sensitivity: ,Not on the permitted application list,Application hash: 1385D3126CF60DB8BB18D1AD1EEFAD41325DF0F846AB7A0A60D3A75A4D418755,Hash type: SHA2,Company name: ,Application name: login[1].htm,Application version: ,Application type: 127,File size (bytes): 3047,Category set: {sep_set},Category type: {sep_type},Location: Default'.format(datestamp=datestamp, src=src, srcprt=srcprt, datestamp2=datestamp2, hostname=hostname, ext_ip=ext_ip, ext_host=ext_host, category=category, risk=risk, misc=misc, sep_set=sep_set, sep_type=sep_type, sep_aa=sep_aa, sep_ra=sep_ra, sep_sa=sep_sa, username=username)






   print MESSAGE
   sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
   sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
   sleep_timer = (random.randrange(1,10)/4)
   time.sleep(sleep_timer)

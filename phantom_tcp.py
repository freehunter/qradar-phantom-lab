import socket
import logging
import random
import time

while True:
   #We're going to read from a list of usernames
   username = random.choice(list(open('usernames.txt'))).rstrip()

   #We're going to read from a list of hostnames and IP addresses
   windows_src = random.choice(list(open('windows.txt'))).rstrip()
   winhostname = windows_src.split(",")[0]
   winsrc = windows_src.split(",")[1]
   
   windows_dst = random.choice(list(open('windows.txt'))).rstrip()
   windst = windows_dst.split(",")[1]
   
   #Same for hostnames
   #winhostname = random.choice(list(open('win-hostnames.txt'))).rstrip()

   #and ports
   srcprt = random.choice(list(open('prt.txt'))).rstrip()
   dstprt = random.choice(list(open('prt.txt'))).rstrip()

   #Pick randomly between log source types to send
   choice = [5]
   msg = random.choice(choice)

   #send our logs
   #Bluecoat messages
   if msg == 1:
      MESSAGE = 'Bluecoat|src=10.69.38.44|srcport=53148|dst=34.233.103.206|dstport=443|username={username}|devicetime=[10/04/2018:16:22:12 GMT]|s-action=TCP_TUNNELED|sc-status=200|cs-method=CONNECT|time-taken=8311|sc-bytes=586|cs-bytes=1720|cs-uri-scheme=tcp|cs-host=srv-2018-04-10-16.pixel.parsely.com|cs-uri-path=/|cs-uri-query=-|cs-uri-extension=-|cs-auth-group=PMUSA\PMU%20UR%20Web%20Access%20Users|rs(Content-Type)=-|cs(User-Agent)=Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko|cs(Referer)=-|sc-filter-result=OBSERVED|filter-category=Web_Ads/Analytics|cs-uri=tcp://srv-2018-04-10-16.pixel.parsely.com:443/'.format(username=username)
   #Cisco ASA
   elif msg == 2:
      MESSAGE = "<182>Apr 10 2018 16:51:48 IBMRMCFW4110P01 : %ASA-6-302013: Built outbound TCP connection 130168284 for outside:31.13.69.245/443 (31.13.69.245/443) to YELLOW:10.102.196.199/49648 (12.186.185.73/17785)"
   #Windows messages
   elif msg == 4:
      MESSAGE = '<13>Apr 10 12:22:02 {winsrc} AgentDevice=WindowsLog	AgentLogFile=Security	PluginVersion=7.2.7.20	Source=Microsoft-Windows-Security-Auditing	Computer={winhostname}.ibm-sioc.net	OriginatingComputer={winsrc}	User=	Domain=	EventID=4624	EventIDCode=4624	EventType=8	EventCategory=0	RecordNumber=291187011	TimeGenerated=1523377315	TimeWritten=1523377315	Level=Log Always	Keywords=Audit Success	Task=SE_ADT_LOGON_LOGON	Opcode=Info	Message=An account was successfully logged on.  Subject:  Security ID:  NULL SID  Account Name:  -  Account Domain:  -  Logon ID:  0x0  Logon Type:   3  Impersonation Level:  Impersonation  New Logon:  Security ID:  SIOC\{username}  Account Name:  {username}  Account Domain:  SIOC  Logon ID:  0xF0719436  Logon GUID:  {{00000000-0000-0000-0000-000000000000}}  Process Information:  Process ID:  0x0  Process Name:  -  Network Information:  Workstation Name: {winhostname}  Source Network Address: {windst}  Source Port:  {srcprt}  Detailed Authentication Information:  Logon Process:  NtLmSsp'.format(winsrc=winsrc,windst=windst,winhostname=winhostname,srcprt=srcprt,username=username)
   elif msg == 5:
      #We're going to read from a list of hostnames and IP addresses
      src_address = random.choice(list(open('linux.txt'))).rstrip()
      hostname = src_address.split(",")[0]
      src = src_address.split(",")[1]

      dst_address = random.choice(list(open('linux.txt'))).rstrip()
      dst = dst_address.split(",")[1]
      
      MESSAGE = '<14>1 2018-04-10T17:40:13.308962-04:00 {hostname} sshd[5279]: Connection from {src} port {dstprt} on {src} port 22'.format(hostname=hostname, src=src, dstprt=dstprt, srcprt=srcprt)
   #print "UDP target IP:", UDP_IP
   #print "UDP target port:", UDP_PORT
   print MESSAGE

   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect(('192.168.1.196', 514))
   s.sendall(MESSAGE)
   s.close()

   time.sleep(1)

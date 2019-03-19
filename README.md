# Phantom lab

Fakes realistic looking syslog traffic on a QRadar system

Copy all the files (including text files) to the QRadar system

Run with 'nohup python /your/directory/phantom.py &' to push to background and keep running while you're logged out. Run setip.sh the first time you install or after an update to make sure your QRadar's console IP is set inside the script. 

Will trigger UBA (User Behavior Analytics) as well as many of the default rules. Useful to generate realistic-looking traffic and trigger rules on a test or lab system


Troubleshooting:

**Logs not being seen in Log Activity** - Check consoleip.txt to make sure the console's EP is set correctly. Run setip.sh or manually enter the correct IP

**Logs seen an unknown generic log events** - Almost all of the events that ship with phantom lab should be parsed with default DSMs in QRadar. It does take some time for the logs to be recognized and log sources to be added, maybe 10-15 minutes. 

**Windows log sources** - Windows log sources will have to be manually added to log source list. This can be done in bulk by downloading the win-hostnames.txt list (not IP addresses!) and bulk adding a Windows syslog log source. There is an included LSX you can upload to help additional parsing for these events.


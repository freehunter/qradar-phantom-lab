# Phantom lab

Fakes realistic looking syslog traffic on a QRadar system

Copy all the files (including text files) to the QRadar system

Run with 'nohup python /your/directory/phantom.py &' to push to background and keep running while you're logged out

Will trigger UBA (User Behavior Analytics) as well as many of the default rules. Useful to generate realistic-looking traffic and trigger rules on a test or lab system
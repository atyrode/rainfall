import os
import sys

def vulnerable(input):
    
    # If the input string doesn't translate to the int 423
    if int(input) != 423:
        print "No !"
        return
    
    # We get the *effective* gid and the uid of the current process
    gid = os.getegid()
    uid = os.geteuid()
    
    # We set the real, effective and saved gid to the effective gid and the real and saved uid to the effective uid
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    
    # We execute the shell
    os.execl("/bin/sh", "sh")
    
if __name__ == '__main__':
    vulnerable(sys.argv[1]) # Imitiates the segfault failure if no argument is passed
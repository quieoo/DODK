
import os
import time

def run():
    pid=os.fork()
    if pid==0:
        os.execv('../build/app/app_simple_fwd_vnf', ['foo', '-h'])
        
    else:
     print('father')

run()
#!/usr/bin/env python
#-*-coding:utf-8-*-

import sys
import os

from patches_tool import sshutils


def main():
    ip_list = ['172.28.0.4', '172.28.0.2']
    file_list = ['execute.sh', 'su_change.sh']
    src_base_path = '/home'
    des_base_path = '/home/fsp/'
    
    for ip in ip_list:
        ssh = sshutils.SSH(host=ip, user='fsp', password='Huawei@CLOUD8')
        for f in file_list:
            src_file = os.path.join(src_base_path, f)
            dest_file = os.path.join(des_base_path, f)
            ssh.put_file(src_file, dest_file)
        
        ssh.execute('cd %s; sh execute.sh' % des_base_path)
        ssh.close()

if __name__ == "__main__":
    sys.exit(main())

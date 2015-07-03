#!/usr/bin/expect

spawn su -
expect "Password:"
send "Huawei@CLOUD8!\r"
expect "#"
send "sed -i \"/PermitRootLogin no/s//PermitRootLogin yes/g\" /etc/ssh/sshd_config ;service sshd restart\r"
send "exit\r"
expect eof

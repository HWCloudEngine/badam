ReadMe
Author: Nash and Lu QiTao
Email: nash_xiejun@163.com

For use hybrid cloud patch, need to do following steps:
Step 1. Modify config files.
Modify "patches_tool/patches_tool_config.ini"
Modify "patches_tool/aws_patch/aws_config.ini"
Modify "patches_tool/vcloud_patch/vcloud_config.json"

Step 2. Copy patches_tool folder to cascading node.
e.g. copy to /root/ directory.

Step 3. Run config.py in cascading node as following:
# cd /root/patches_tool/
# python config.py prepare
After finish prepare, then start to do cascading config by following commands:
# python config.py cascading 

Step 4. Verify service status and basic function of FS5.1
To check service status by execute following commands:
# cd /root/patches_tool/
# python config.py check
If everything is ok, means we have finish to install and config FS5.1.
We can by create a VM in az01/az11/az31 from cascading node to check basic function.
After finish verification, please clear up your test data. 

Step 5. Patch hybrid_cloud patches to cascading node and proxy node.
In cascading node, execute following commands to patch Hybrid-Cloud patches.
# cd /root/patches_tool/
# python patches_tool.py
By running "# python patches_tool.py", it will copy patches to cascading,proxy and cascaded nodes,
and it will restart services to let patches take effect.
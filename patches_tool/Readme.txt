ReadMe
Author: nash
Email: nash_xiejun@163.com

For use hybrid cloud patch, need to do following steps:
Step 1. Modify config file "patches_tool_config.ini"

Step 2. Copy patches_tool folder to cascading node and cascaded node.

Step 3. Run config.py in cascading node/cascaded node
In cascading node, to run config.py by "# python config.py cascading"
In each cascaded node, to run config.py by "# python config.py cascaded"
By running "# python config.py check", user can check services status.
By running "# python config.py restart", user can restart services. 

Step 4. Verify service status and basic function of FS5.1
When arrived here, if everything is ok, means we have finish to install and config FS5.1.
We can by create a VM in az01/az11/az31 from cascading node to check basic function.
After finish verification, please clear up your test data. 

Step 5. Patch hybrid_cloud patches to cascading node and proxy node.
By running "# python patches_tool.py", it will copy patches to cascading and proxy node,
and it will restart services to let patches take effect.


For patch hybrid_patches in cascaded node for aws and vcloud, please refer to \patches_tool\aws_patch\Readme.txt and \patches_tool\vcloud_patch\Readme.txt
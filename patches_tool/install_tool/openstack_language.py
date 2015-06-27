#!/usr/bin/env python
#-*-coding:utf-8-*-

#打印的内容，中英文对照表
CLOUD_ADMIN_PASSWORD = ["Please input the password of cloud_admin:", "请输入cloud_admin用户的密码："]
CLOUD_ADMIN_WRONG = ["Please input correct password or check keystone !", "请输入正确的密码!"]
DZ_ADMIN_PASSWORD = ["Please input the password of dc_admin:", "请输入dc_admin用户的密码："]
VM_MANAGER_INPUT = ["Can virtual machine be deployed in the controller node?[y/n] [%s]", "虚拟机能否部署在管理节点？[y/n][%s]"]
VM_SECURITY_INPUT = ["Whether open network security group [y|n][%s]", "是否打开网络安全组 [y|n][%s]"]
SECURITY_TIP = ["Tips: If you have deployed a virtual machine, you need to delete the virtual machine first, and then modify the security group, and finally re-create the virtual machine","提示：如果你部署了虚拟机，需要先删除虚拟机，然后修改安全组，最后重新创建虚拟机"]
SECURITY_INPUT = ["Do you want to modify the security group [y|n][n]","请问您是否需要修改安全组"]
NETWORK_TYPE_INPUT = ["Do you want to modify network type [y|n][n]", "请问您是否修改网络类型 [y|n][n]"]
VXLAN_INPUT = ["Do you want to use default priority of vxlan for network type [y|n][%s]", "请问您是否默认优先选择vxlan类型 [y|n][n]"]
CURRENT_CONFIG = ["Current config data of openstack is :", "当前openstack的配置数据如下："]
CONFIG_DATA_OR_NOT = ["Please confirm the config data, 's' for save, 'c' for cancel![s/c][s]:", "请确认配置数据！保存为‘s’,取消为‘c’["
                                                                                           "s/c][s]："]
DELETE_DATA_OR_NOT = ["Please confirm the DELETE data, 'd' for save, 'c' for cancel![d/c][d]:", "请确认配置数据！删除为‘d’,取消为‘c’["
                                                                                           "d/c][d]："]
INPUT_ERROR = ["Please input correct character!", "请输入正确的字符!"]
INTERNAL_ERROR = ["Internal error,please Contact maintenance person!", "内部错误，请联系维护人员！"]
REFER_LOG_ERROR = ["Fail to set %s,refer to log!", "设置%s失败，具体原因请查询日志！"]
SUCCESS_ERROR = ["Suceess to set %s!", "设置%s成功！"]
EDNPOINT_MSG = ["Current mode of endpoints:\n%s\nplease input the item number needed be modified [s].",
                "目前选择创建endpoint模式为\n%s\n请输入需要修改的编号 [s]。"]

CPS_COMMIT_SUCCESS = ["Succeed to save %s!", "%s的配置生效!"]
PASSWORD_MORE_THAN_THREE = ["Quit due to 3 failed PASSWORD!", "输入密码错误超过三次，系统退出！"]
SAVE_AND_QUIT = ["[s]save&quit","[s]保存并退出"]
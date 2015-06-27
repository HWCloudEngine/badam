#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import cps_server
from fs_keystone_server import PasswordException
import fs_keystone_server
import fs_log_util
import fs_nova_constant
from fs_nova_util import NovaUtil
from openstack_language import VM_MANAGER_INPUT, CPS_COMMIT_SUCCESS
import os
import sys
import traceback
from openstack_language import INPUT_ERROR, INTERNAL_ERROR, REFER_LOG_ERROR, SUCCESS_ERROR
from print_msg import PrintMessage
import fsutils as utils
from os.path import join
import fs_change_util

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class Nova():
    """
    处理nova相关组件，主要处理虚拟机是否部署在控制节点上。
    """
    vm_manager = None
    dz_password = None

    def __init__(self):
        self.is_wdt_changed = False
        self.vm_manager = "n"


    def get_section_list(self):
        return [fs_nova_constant.SECTION_NOVA_CONFIG]


    def get_file_path(self):
        return fs_nova_constant.NOVA_INI_PATH


    # 1.Vm deploy policy
    def _vm_manager_config(self):
        """
        配置是否虚拟机部署在管理节点上。
        """
        value = NovaUtil().nova_get_data_by_key(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_TENANT)
        if value is not None:
            self.vm_manager = value
        else:
            self.vm_manager = "n"

        while 1:
            vm_manage_temp = raw_input(PrintMessage.get_msg_ex(VM_MANAGER_INPUT, self.vm_manager))
            if vm_manage_temp == "y" or vm_manage_temp == "n":
                self.vm_manager = vm_manage_temp
                break
            elif vm_manage_temp == "":
                break
            else:
                PrintMessage.print_msg(INPUT_ERROR, True)

        #保存到文件中
        datas = {fs_nova_constant.SECTION_NOVA_CONFIG_TENANT: self.vm_manager}
        flag = NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, datas)
        if not flag:
            LOG.error("fail to process file.")
            PrintMessage.print_msg(INTERNAL_ERROR, True)
            sys.exit(0)

    def _vm_manager_validate(self, type, phase):
        """
        生效虚拟机是否部署在管理节点上。
        """
        LOG.info("Begin to validate _vm_manager_validate.type is %s,phase is %s." % (str(type), str(phase)))

        try:
            cf = NovaUtil().nova_get_config()
            if cf is None:
                return
            if not cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_TENANT):
                return True
            self._manage_validate(cf)
        except PasswordException:
            #对于密码错误的情况，直接将该异常抛给框架
            raise PasswordException("quit due to 3 failed password")
        except Exception:
            LOG.error("fail to validate.traceback:%s" % traceback.format_exc())
            PrintMessage.print_msg(INTERNAL_ERROR, True)
            sys.exit(0)
        LOG.info("End to validate nova.type is %s,phase is %s." % (str(type), str(phase)))

    def _manage_validate(self, cf):
        """
        处理虚拟机能否部署在管理节点
        """
        vm_boot_flag = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_TENANT)
        #输入dz_admin的密码
        self._dz_password_config()

        if vm_boot_flag == "n":
            #若不允许部署在管理节点上，则将控制节点加入到aggr。
            if not NovaUtil().create_aggr_for_ctrl_host():
                PrintMessage.print_msg_ex(REFER_LOG_ERROR, "vm deploy policy", True)
                sys.exit(1)
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "vm deploy policy")
        else:
            #若允许部署在管理节点上，则将控制节点从aggr中删除。
            if not NovaUtil().rmv_aggr_for_ctrl_host():
                PrintMessage.print_msg_ex(REFER_LOG_ERROR, "vm deploy policy", True)
                sys.exit(1)
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "vm deploy policy")

    # 2.Watchdog
    def _watch_dog_time_config(self):
        wdt_start_time = 0
        wdt_reboot_time = 0
        while 1:
            print '[1] Open'
            print '[2] Close'
            print '[q] Quit'
            query_open_watchdog_str = "Do you want to open watchdog for VM?[1|2][q]:"
            input_string = raw_input(query_open_watchdog_str)
            if input_string == '1':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_WATCHDOG: "true"} 
                NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                break
            elif input_string == '2':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_WATCHDOG: "false"}
                NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                return 
            elif  input_string == '' or  input_string == 'q':
                return 
            else:
                print "Error input,please check."
                continue
            
        while 1:
            def_wdt_start_time = "0"
            output_string = "Timeout of start:[%s]" % def_wdt_start_time
            input_string = raw_input(output_string)
            if input_string == '':
                input_string = def_wdt_start_time
            wdt_start_time = input_string
            break

        while 1:
            def_wdt_reboot_time = '0'
            output_string = "Timeout of reboot:[%s]" % def_wdt_start_time
            input_string = raw_input(output_string)
            if input_string == '':
                input_string = def_wdt_reboot_time
            wdt_reboot_time = input_string
            break
        data = {fs_nova_constant.SECTION_NOVA_CONFIG_WDT_REBOOT_TIME: wdt_reboot_time,
                fs_nova_constant.SECTION_NOVA_CONFIG_WDT_START_TIME: wdt_start_time}
        NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)

    def _watch_dog_time_validate(self, type_name, phase):
        LOG.error("_watch_dog_time_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return
        if not cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_TENANT):
            return True

        data = {}
        changeFlag = False
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_WATCHDOG):
            instance_vwatchdog = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                        fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_WATCHDOG)
            changeFlag = True
            data["instance_vwatchdog"] = instance_vwatchdog

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_WDT_REBOOT_TIME) and cf.has_option(
                fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_WDT_START_TIME):
            changeFlag = True
            wdt_reboot_time = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                     fs_nova_constant.SECTION_NOVA_CONFIG_WDT_REBOOT_TIME)
            wdt_start_time = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                    fs_nova_constant.SECTION_NOVA_CONFIG_WDT_START_TIME)
            data["wdt_reboot_time"] = wdt_reboot_time
            data["wdt_start_time"] = wdt_start_time
        if changeFlag:
            self.update_nova_compute(data)
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "watchdog")

    def update_nova_compute(self, cfg_dict):
        return cps_server.update_template_params('nova', 'nova-compute', cfg_dict)

    def update_nova_scheduler(self, cfg_dict):
        return cps_server.update_template_params('nova', 'nova-scheduler', cfg_dict)

    #3. Console log
    def _instance_console_log_config(self):
        while 1:
            print '[1] Open'
            print '[2] Close'
            print '[q] Quit'
            input_string = raw_input('Do you want to open log funtion for VM console? [1|2|q][q]')
            if input_string == '' or input_string == 'q':
                return
            if input_string == '1':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_CONSOLE: "true"}
                break
            if input_string == '2':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_CONSOLE: "false"}
                break
            print 'Please input correct choose [1|2|q]'
            continue
        NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)

    def _instance_console_log_validate(self, type_name, phase):
        LOG.info("_watch_dog_time_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_CONSOLE):
            instance_console_log = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                          fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_CONSOLE)
            self.update_nova_compute({"instance_console_log": instance_console_log})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "console log")
        return True


    #4. Memory Qos
    def _instance_memory_qos_config(self):
        while 1:
            print '[1] Open'
            print '[2] Cloase'
            print '[q] Quit'
            input_string = raw_input('Do you want to open memory Qos for vm? [1|2|q][q]')
            if input_string == '' or input_string == 'q':
                return
            if input_string == '1':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_MEMORY_QOS: "true"}
                break
            if input_string == '2':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_MEMORY_QOS: "false"}
                break
            print 'Please input correct choose [1|2|q]'
            continue
        NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)

    def _instance_memory_qos_validate(self,type_name, phase):
        LOG.info("_watch_dog_time_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_MEMORY_QOS):
            instance_memory_qos = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                         fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_MEMORY_QOS)
            self.update_nova_compute({"instance_memory_qos": instance_memory_qos})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "memory qos")
        return True

    #5. Nic interrupts
    def _input_nic_suspension_config(self):
        while 1:
            print '[1] Yes'
            print '[2] No'
            print '[q] Quit'
            input_string = raw_input('Do you want to bond nic interrupt to cpu? [1|2|q][q]')
            if input_string == '' or input_string == 'q':
                return
            if input_string == '1':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_NIC_SUSPENSION: "true"}
                break
            if input_string == '2':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_NIC_SUSPENSION: "false"}
                break
            print 'Please input correct choose [1|2|q]'
            continue
        NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)

    def _input_nic_suspension_validate(self,type_name, phase):
        LOG.info("_input_nic_suspension_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_NIC_SUSPENSION):
            nic_suspension = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                    fs_nova_constant.SECTION_NOVA_CONFIG_NIC_SUSPENSION)
            self.update_nova_compute({"nic_suspension": nic_suspension})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "nic interrupts")

    #6.Kbox
    def _input_kbox_config(self):
        while 1:
            print '[1] Open kbox'
            print '[2] Close kbox'
            print '[q] Quit'
            input_string = raw_input('Would you like to open Kbox? [1|2|q][q]')
            if input_string == '' or input_string == 'q':
                return
            if input_string == '1':
                use_nonvolatile_ram = self._input_use_nonvolatile_ram()
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_IS_OPEN_K_BOX: "true",
                        fs_nova_constant.SECTION_NOVA_CONFIG_USER_NONVOLATILE_RAM: use_nonvolatile_ram}
                NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                return
            if input_string == '2':
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_IS_OPEN_K_BOX: "false",
                        fs_nova_constant.SECTION_NOVA_CONFIG_USER_NONVOLATILE_RAM: "false"}
                NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                return
            print "Please input correct choose [1|2|q]"
            continue

    def _input_use_nonvolatile_ram(self):
        while 1:
            print 'This option requires hardware support open.'
            print 'See detailed rules operating manual.'
            input_string = raw_input("Do you want to use use_nonvolatile_ram  [y|n|n]")
            if input_string == '' or input_string == 'n':
                return 'false'
            if input_string == 'y':
                return 'true'
            print 'Please input correct choose [y|n|n]'
            continue

    def _input_kbox_validate(self,type_name, phase):
        LOG.info("_input_kbox_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_IS_OPEN_K_BOX):
            is_open_kbox = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                  fs_nova_constant.SECTION_NOVA_CONFIG_IS_OPEN_K_BOX)
            if is_open_kbox.lower() == 'true':
                if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                                 fs_nova_constant.SECTION_NOVA_CONFIG_USER_NONVOLATILE_RAM):
                    use_nonvolatile_ram = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                                 fs_nova_constant.SECTION_NOVA_CONFIG_USER_NONVOLATILE_RAM)
                    self.update_nova_compute(
                        {"send_nmi_message": "true", "instance_vwatchdog": "true", "use_kbox": "true",
                         "use_nonvolatile_ram": use_nonvolatile_ram})
            if is_open_kbox.lower() == 'false':
                self.update_nova_compute(
                    {"send_nmi_message": "false", "instance_vwatchdog": "false", "use_kbox": "false",
                     "use_nonvolatile_ram": "false"})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "kbox")

    #7. Overcommitting
    def _input_advance(self):
        self.input_cpu_allocation_ratio()

    def input_cpu_allocation_ratio(self):
        print 'Tips :Configuration This item may result in poor system performance'
        while 1:
            input_string = raw_input('Please set Cpu_allocation_ratio :')
            if input_string == '':
                continue
            if not check_str_is_number(input_string):
                print 'Please input the correct ratio...'
                continue
            data = {fs_nova_constant.SECTION_NOVA_CONFIG_CPU_ALLOCATION_RATIO: input_string}
            NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
            return

    def input_cpu_allocation_ratio_validate(self,type_name, phase):
        LOG.info("input_cpu_allocation_ratio_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_CPU_ALLOCATION_RATIO):
            cpu_allocation_ratio = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                          fs_nova_constant.SECTION_NOVA_CONFIG_CPU_ALLOCATION_RATIO)
            self.update_nova_scheduler({"cpu_allocation_ratio": cpu_allocation_ratio})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "overcommitting")


    def input_disk_allocation_ratio(self):
        print 'Tips :Configuration This item may result in poor system performance'
        while 1:
            input_string = raw_input('Please set Disk_allocation_ratio :')
            if input_string == '':
                continue
            while 1:
                input_flag = raw_input("Are you sure set Disk_allocation_ratio to %s [y|n][n]?" % input_string)
                if input_flag == 'n' or input_flag == '':
                    return
                if input_flag == 'y':
                    data = {fs_nova_constant.SECTION_NOVA_CONFIG_DISK_ALLOCATION_RATIO: input_string}
                    NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                    return
                print "Please input correct choose [y|n]"
                continue

    def input_ram_allocation_ratio(self):
        print 'Tips :Configuration This item may result in poor system performance'
        while 1:
            input_string = raw_input('Please set Ram_allocation_ratio :')
            if input_string == '':
                continue
            while 1:
                input_flag = raw_input("Are you sure set Ram_allocation_ratio to %s [y|n][n]?" % input_string)
                if input_flag == 'n' or input_flag == '':
                    return
                if input_flag == 'y':
                    data = {fs_nova_constant.SECTION_NOVA_CONFIG_RAM_ALLOCATION_RATIO: input_string}
                    NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                    return
                print "Please input correct choose [y|n]"
                continue

    #8. Vm HA
    def _input_vm_ha_func(self):
        flag = None
        while 1:
            print "[1] Open"
            print "[2] Close"
            print "[q] Quit"
            inputstr = raw_input("Do you want to open HA function for VM? [1|2|q][2]")
            if inputstr == '1':
                flag = "True"
            if inputstr == '2' or inputstr == '':
                flag = "False"
            if inputstr == 'q':
                return
            if not flag is None:
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_HA_FLAG: flag}
                NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                return
            print "please input [1|2|s]"
            continue

    def _input_vm_ha_func_validate(self,type_name, phase):
        LOG.info("_input_vm_ha_func_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_HA_FLAG):
            ha_flag = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                             fs_nova_constant.SECTION_NOVA_CONFIG_HA_FLAG)
            cps_server.update_template_params("heat", "heat", {"ha_policy_enable": ha_flag})
            cps_server.update_template_params("cps", "cps-client", {"ha_policy_enable": ha_flag})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "vm ha")

    #9. Image across AZs
    def _input_upload_volume_to_image(self):
        flag = None
        while 1:
            input_str = raw_input("Do you want to share images between different AZs? [y|n][n]")
            if input_str == 'y':
                flag = "True"
            if input_str == 'n' or input_str == '':
                flag = "False"
            if not flag is None:
                data = {fs_nova_constant.SECTION_NOVA_CONFIG_UPLOAD_VOLUME_TO_IMAGE: flag}
                NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                return
            print "please input [y|n|n]"
            continue

    def _input_upload_volume_to_image_validate(self, type_name, phase):
        LOG.info("_watch_dog_time_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_UPLOAD_VOLUME_TO_IMAGE):
            upload_volume_to_image = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                            fs_nova_constant.SECTION_NOVA_CONFIG_UPLOAD_VOLUME_TO_IMAGE)
            cps_server.update_template_params("nova", "nova-api", {"upload_volume_to_image": upload_volume_to_image})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "image across AZs")

    #10. Instance name template
    def _input_instance_name_template(self):
        while 1:
            input_str = raw_input("Please set  instance_name_template :")
            if not input_str == '':
                data = {fs_nova_constant.SECTION_NOVA_INSTANCE_NAME_TEMPLATE: input_str}
                NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, data)
                break
            continue

    def _input_instance_name_template_validate(self, type_name, phase):
        LOG.info("input_instance_name_template_validate type =%s, phase =%s."%(type_name, phase))
        cf = NovaUtil().nova_get_config()
        if cf is None:
            return True
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_INSTANCE_NAME_TEMPLATE):
            instance_name_template = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                            fs_nova_constant.SECTION_NOVA_INSTANCE_NAME_TEMPLATE)
            cps_server.update_template_params("nova", "nova-api", {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-novncproxy",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-conductor",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-console",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-scheduler",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-compute",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-network",
                                              {"instance_name_template": instance_name_template})
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "instance name template")

    #11. Nova scheduler HA mode
    def update_template_ha_mode(self, cfg_dict):
        #首先，获得cps-server中nova-scheduler的hamode
        dict = {}
        dict = cps_server.get_template_info(cfg_dict["service"], cfg_dict["template"])

        #比较用户输入的hamode与获得的hanmode是否一致
        if dict["hamode"] == cfg_dict["hamode"]:
            print "%s HA mode is %s, you needn't to configure." % (cfg_dict["template"], dict["hamode"])
        else:
            #修改nova-scheduler的hamode为用户输入模式

            dict["hamode"] = cfg_dict["hamode"]
            cps_server.update_template_info(cfg_dict["service"], cfg_dict["template"], dict)
            cps_server.cps_commit()
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "nova scheduler ha mode")

    def _input_nova_scheduler_ha_mode(self):
        while 1:
            print "[1] Active-active"
            print "[2] Active-standby"
            print "[q] Quit"
            inputstr = raw_input("Please input the Nova scheduler HA mode:[1|2|q][1]:")
            if inputstr == '1' or inputstr == "":

                self.update_template_ha_mode({"role":"controller", "service":"nova", \
                                                "template":"nova-scheduler", "hamode":"active-active"})
                break
            elif inputstr == '2':
                self.update_template_ha_mode({"role":"controller", "service":"nova", \
                                                "template":"nova-scheduler", "hamode":"active-standby"})

                break
            elif inputstr == 'q':
                break
            else:
                print "Please input correctly!"


    def create_def_config(self, cf):
        """
        快速部署时调用，将数据写入default.ini中
        """
        LOG.info("create_def_config cf"%cf)
        datas = {fs_nova_constant.SECTION_NOVA_CONFIG_TENANT: "n"}
        flag = NovaUtil().nova_write_data(fs_nova_constant.SECTION_NOVA_CONFIG, datas)
        if not flag:
            LOG.error("fail to process file.")
            PrintMessage.print_msg(INTERNAL_ERROR, True)
            sys.exit(0)


    def config(self, type_name):
        """
        配置nova的相关配置项
        """
        while 1:
            print "[1] Vm deploy policy"
            print "[2] Watchdog"
            print "[3] Console log"
            print "[4] Memory Qos"
            print "[5] Nic interrupts"
            print "[6] Kbox"
            print "[7] Overcommitting"
            print "[8] Vm HA"
            print "[9] Image across AZs"
            print "[10]Instance name template"
            print "[11]Nova scheduler HA mode"
            print "[s] Save&quit"
            def_input = 's'
            output_string = "Please choose [1-11|s][%s]" % def_input
            input_string = raw_input(output_string)
            if input_string == '1':
                #设置虚拟机是否能部署在管理节点
                self._vm_manager_config()
                self._vm_manager_validate(type_name,None)
                continue
            if input_string == '2':
                self._watch_dog_time_config()
                self._watch_dog_time_validate(type_name,None)
                continue
            if input_string == '3':
                self._instance_console_log_config()
                self._instance_console_log_validate(type_name, None)
                continue
            if input_string == '4':
                self._instance_memory_qos_config()
                self._instance_memory_qos_validate(type_name, None)
                continue
            if input_string == '5':
                self._input_nic_suspension_config()
                self._input_nic_suspension_validate(type_name, None)
                continue
            if input_string == '6':
                self._input_kbox_config()
                self._input_kbox_validate(type_name, None)
                continue
            if input_string == '7':
                self._input_advance()
                self.input_cpu_allocation_ratio_validate(type_name, None)
                continue
            if input_string == '8':
                self._input_vm_ha_func()
                self._input_vm_ha_func_validate(type_name, None)
                continue
            if input_string == '9':
                self._input_upload_volume_to_image()
                self._input_upload_volume_to_image_validate(type_name, None)
                continue
            if input_string == '10':
                self._input_instance_name_template()
                self._input_instance_name_template_validate(type_name, None)
                continue
            if input_string == '11':
                self._input_nova_scheduler_ha_mode()
                continue
            if input_string == 's' or input_string == '':
                break
            print "Please input correct choose."
            print ""
        return True


    def validate(self, type_name, phase):
        #这个流程 只有走文件生效的时候才能进去生效，其他配置退出的时候，直接保存生效了
        if not fs_change_util.is_section_change(fs_change_util.NOVA_TYPE):
            return
        LOG.info("validate type =%s, phase =%s."%(type_name, phase))
        #1
        self._vm_manager_validate(type_name,None)
        #2
        self._watch_dog_time_validate(type_name,None)
        #3
        self._instance_console_log_validate(type_name,None)
        #4
        self._instance_memory_qos_validate(type_name, None)
        #5
        self._input_nic_suspension_validate(type_name, None)
        #6
        self._input_kbox_validate(type_name, None)
        #7
        self.input_cpu_allocation_ratio_validate(type_name, None)
        #8
        self._input_vm_ha_func_validate(type_name, None)
        #9
        self._input_upload_volume_to_image_validate(type_name, None)
        #10
        self._input_instance_name_template_validate(type_name, None)

    def validate_params(self, cf):
        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_WDT_REBOOT_TIME) and cf.has_option(
                fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_WDT_START_TIME):
            wdt_reboot_time = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                     fs_nova_constant.SECTION_NOVA_CONFIG_WDT_REBOOT_TIME)
            wdt_start_time = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                    fs_nova_constant.SECTION_NOVA_CONFIG_WDT_START_TIME)
            self.update_nova_compute({'wdt_reboot_time': wdt_reboot_time, 'wdt_start_time': wdt_start_time})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_WATCHDOG):
            instance_vwatchdog = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                        fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_WATCHDOG)
            self.update_nova_compute({"instance_vwatchdog": instance_vwatchdog})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_CONSOLE):
            instance_console_log = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                          fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_CONSOLE)
            self.update_nova_compute({"instance_console_log": instance_console_log})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_MEMORY_QOS):
            instance_memory_qos = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                         fs_nova_constant.SECTION_NOVA_CONFIG_INSTANCE_MEMORY_QOS)
            self.update_nova_compute({"instance_memory_qos": instance_memory_qos})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_NIC_SUSPENSION):
            nic_suspension = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                    fs_nova_constant.SECTION_NOVA_CONFIG_NIC_SUSPENSION)
            self.update_nova_compute({"nic_suspension": nic_suspension})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_IS_OPEN_K_BOX):
            is_open_kbox = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                  fs_nova_constant.SECTION_NOVA_CONFIG_IS_OPEN_K_BOX)
            if is_open_kbox.lower() == 'true':
                if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                                 fs_nova_constant.SECTION_NOVA_CONFIG_USER_NONVOLATILE_RAM):
                    use_nonvolatile_ram = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                                 fs_nova_constant.SECTION_NOVA_CONFIG_USER_NONVOLATILE_RAM)
                    self.update_nova_compute(
                        {"send_nmi_message": "true", "instance_vwatchdog": "true", "use_kbox": "true",
                         "use_nonvolatile_ram": use_nonvolatile_ram})
            if is_open_kbox.lower() == 'false':
                self.update_nova_compute(
                    {"send_nmi_message": "false", "instance_vwatchdog": "false", "use_kbox": "false",
                     "use_nonvolatile_ram": "false"})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_CPU_ALLOCATION_RATIO):
            cpu_allocation_ratio = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                          fs_nova_constant.SECTION_NOVA_CONFIG_CPU_ALLOCATION_RATIO)
            self.update_nova_scheduler({"cpu_allocation_ratio": cpu_allocation_ratio})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_DISK_ALLOCATION_RATIO):
            disk_allocation_ratio = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                           fs_nova_constant.SECTION_NOVA_CONFIG_DISK_ALLOCATION_RATIO)
            self.update_nova_scheduler({"disk_allocation_ratio": disk_allocation_ratio})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_RAM_ALLOCATION_RATIO):
            ram_allocation_ratio = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                          fs_nova_constant.SECTION_NOVA_CONFIG_RAM_ALLOCATION_RATIO)
            self.update_nova_scheduler({"ram_allocation_ratio": ram_allocation_ratio})
            self.update_nova_compute({"ram_allocation_ratio": ram_allocation_ratio})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG, fs_nova_constant.SECTION_NOVA_CONFIG_HA_FLAG):
            ha_flag = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                             fs_nova_constant.SECTION_NOVA_CONFIG_HA_FLAG)
            cps_server.update_template_params("heat", "heat", {"ha_policy_enable": ha_flag})
            cps_server.update_template_params("cps", "cps-client", {"ha_policy_enable": ha_flag})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_CONFIG_UPLOAD_VOLUME_TO_IMAGE):
            upload_volume_to_image = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                            fs_nova_constant.SECTION_NOVA_CONFIG_UPLOAD_VOLUME_TO_IMAGE)
            cps_server.update_template_params("nova", "nova-api", {"upload_volume_to_image": upload_volume_to_image})
            cps_server.cps_commit()

        if cf.has_option(fs_nova_constant.SECTION_NOVA_CONFIG,
                         fs_nova_constant.SECTION_NOVA_INSTANCE_NAME_TEMPLATE):
            instance_name_template = cf.get(fs_nova_constant.SECTION_NOVA_CONFIG,
                                            fs_nova_constant.SECTION_NOVA_INSTANCE_NAME_TEMPLATE)
            cps_server.update_template_params("nova", "nova-api", {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-novncproxy",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-conductor",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-console",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-scheduler",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-compute",
                                              {"instance_name_template": instance_name_template})
            cps_server.update_template_params("nova", "nova-network",
                                              {"instance_name_template": instance_name_template})
            cps_server.cps_commit()


    def validate_tmp(self, type_name, phase):
        """
    将配置文件中的值生效。主要做如下处理：
    1.创建endpoint；
    2.处理虚拟机能否部署到管理节点
    3.处理网络安全组是否应用
    4.创建虚拟机mac池的范围
    @type：阶段，目前应该都为3.1."deploy"2."deploy & config"3."config"
    """
        LOG.info("Begin to validate nova.type is %s,phase is %s." % (str(type_name), str(phase)))

        try:
            cf = ConfigParser.ConfigParser()
            if not os.path.exists(fs_nova_constant.NOVA_INI_PATH):
                #若配置文件不存在，则直接退出
                LOG.error("default.ini doesn't exist,file is %s." % fs_nova_constant.NOVA_INI_PATH)
                PrintMessage.print_msg(INTERNAL_ERROR, True)
                sys.exit(0)
            else:
                cf.read(fs_nova_constant.NOVA_INI_PATH)
            self.validate_params(cf)
            if type_name == utils.TYPE_ONLY_CONFIG:
                self._manage_validate(cf)
                PrintMessage.print_msg_ex(CPS_COMMIT_SUCCESS, "nova")

            #否则，将配置文件中的配置生效
            if type_name == utils.TYPE_ONLY_DEPLOY and phase == utils.PHASE_POST:
                self._manage_validate(cf)
                PrintMessage.print_msg_ex(CPS_COMMIT_SUCCESS, "nova")
        except PasswordException:
            #对于密码错误的情况，直接将该异常抛给框架
            raise PasswordException("quit due to 3 failed password")
        except Exception:
            LOG.error("fail to validate.traceback:%s" % traceback.format_exc())
            PrintMessage.print_msg(INTERNAL_ERROR, True)
            sys.exit(0)
        LOG.info("End to validate nova.type is %s,phase is %s." % (str(type_name), str(phase)))


    def _dz_password_config(self):
        """
        将界面输入的dz_password保存。
        """
        self.dz_password = fs_keystone_server.keystone_get_dc_password()

    def _input_output(self, input_msg):
        """
        界面交互函数。
        @param input_msg:例如【“test”，“你好”】
        @return：用户的输入
        """
        output_msg = raw_input(input_msg)
        return output_msg


def check_str_is_number(data):
    try:
        number = int(data)
        return number >= 0
    except:
        try:
            number = float(data)
            return number >= 0
        except:
            return False

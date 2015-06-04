vcloud计算（wangfeng）
---
1. 只支持发放双网卡vm。
2. 不支持attach卷，detach卷，卷快照。
3. 卷和镜像cache在本地（AZ11的openstack节点上），要保证磁盘空间足够，或者通过quota限制


aws计算（wangfeng）
---
1. 第一次上传镜像创建vm会非常慢（小时级别），无法演示。要提前上传镜像到aws，并建立关联
2. 不建议通过“迁移不带数据卷的vm的数据卷”的方式来创建vm，没有完整测试过。发放vm走正常流程

vcenter计算（liuling）
---
1. 用windows的镜像发放虚拟机，windows镜像必须安装virtIO. 已经验证镜像windows2012


网络有关 (jhj，wj)
---

1. 不支持安全组，不支持防火墙，不支持用户vpn
2. 单vm不支持多用户网络，只支持一个用户网络
2. 用户在创建网络时**不要**使用以下网段：

		162.3.0.0/16
		172.30.32.0/20
		172.30.48.0/20

2. 级联层和被级联层重启后，需要重新配置vpn路由，执行如下命令：

		ip route add 172.30.32.0/20 via 162.3.110.247
		ip route add 172.30.48.0/20 via 172.28.48.1

3. 创建VM后，如果VM不通是由于port bind failed导致的，则需更新port的binding:host_id后，重启VM
判断是否是bind failed的过程如下：

	①找到对应VM的port id

		neutron port-list | grep 192.168.100.x   ##192.168.100.x是虚拟机的IP

	②查看port的详细信息，如果binding为failed，则需要更新binding:host_id,然后重启VM

		neutron port-show xxx 

	③更新port的binding:host_id

		neutron port-update  --binding:host_id=''   <port-uuid>  


router的限制（shangsen）
---

当前L3-Proxy与L3-Agent不能同时运行，版本进行Router调度时存在Bug，解决方法是使用cps的命令将所有L3-Proxy停止，以112.2环境为例，需要在级联层执行以下命令：

		cps host-template-instance-operate --action STOP --service neutron neutron-l3-proxy01
		cps host-template-instance-operate --action STOP --service neutron neutron-l3-proxy02
		cps host-template-instance-operate --action STOP --service neutron neutron-l3-proxy03
		cps host-template-instance-operate --action STOP --service neutron neutron-l3-proxy04
		cps host-template-instance-operate --action STOP --service neutron neutron-l3-proxy05



> 注意：
> 
1. 系统中存在几个L3-Proxy就必须执行几条停止命令；
2. 执行完成后使用neutron agent-list确认L3-Proxy都停止了，由于neutron agent-list是周期性检测，会存在20秒左右时延；
3. 服务器重启之后STOP命令会失效，需要重新执行


Sg限制和容灾限制（yinwei）
---
1. 备份系统卷的快照能在ec2还原出卷数据，但是快照发布为ami后无法启动，亚马逊技术支持回复不支持这种场景。
2. ec2的卷快照无法在sg上导出卷。意味着，一旦sg的卷在ec2上恢复后，如果在ec2上写入了新数据，这些新数据无法导回openstack。
3. 在亚马逊恢复卷的attachment的虚拟机时，受限亚马逊一个region只能创20台虚机。
4. image转化没实现。手动上传image到亚马逊，手动创建或更改ami的Name tag的value为openstack image id。
5. 网络未实现，需要登录亚马逊查看虚机的公网ip。



伸缩组操作约束（shangsen）
---

1. 伸缩组不支持通过资源占用率自动触发伸缩，只支持定时伸缩；
2. 伸缩组初始放置不支持AZ列表为空；
3. 伸缩策略中不指定AZ列表则会根据当前伸缩组AZ列表均衡放置。



3. 
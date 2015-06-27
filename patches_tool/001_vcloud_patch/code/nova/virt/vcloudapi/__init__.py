"""
:mod:`hybridvcloudapi` -- Hybrid vcloud nova support for VMware vCloud through VMware vCloud API.
"""

from nova.virt.vcloudapi import driver

#VCloudDriver = driver.VCloudDriver
VMwareVcloudDriver = driver.VMwareVcloudDriver

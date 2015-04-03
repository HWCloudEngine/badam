"""
:mod:`hybridvmwareapi` -- Hybrid cloud nova support
for VMware vCenter through VMware API.
"""

from nova.virt.hybridvmwareapi import driver

# VMwareESXDriver is deprecated in Juno. This property definition
# allows those configurations to work which reference it while
# logging a deprecation warning
VMwareVCDriver = driver.VMwareVCDriver

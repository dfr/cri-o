package container

import (
	devicecfg "github.com/cri-o/cri-o/internal/config/device"
)

func (c *container) SpecAddDevices(configuredDevices, annotationDevices []devicecfg.Device, privilegedWithoutHostDevices, enableDeviceOwnershipFromSecurityContext bool) error {
	// TODO: implement internal/config/device for FreeBSD and add code here to modify the devfs mount accordingly.

	// After that, add additional_devices from config
	//for i := range configuredDevices {
	//	d := &configuredDevices[i]
	//	c.specAddDevice(d.Device)
	//}

	// Next, verify and add the devices from annotations
	//for i := range annotationDevices {
	//	d := &annotationDevices[i]
	//	c.specAddDevice(d.Device)
	//}

	// Then, add host devices if privileged
	if err := c.specAddHostDevicesIfPrivileged(privilegedWithoutHostDevices); err != nil {
		return err
	}

	// Then, add container config devices
	if err := c.specAddContainerConfigDevices(enableDeviceOwnershipFromSecurityContext); err != nil {
		return err
	}

	// Finally, inject CDI devices
	return c.specInjectCDIDevices()
}

func (c *container) specAddHostDevicesIfPrivileged(privilegedWithoutHostDevices bool) error {
	if !c.Privileged() || privilegedWithoutHostDevices {
		return nil
	}

	// Modify the devfs mount to add all devices
	for i, m := range c.Spec().Config.Mounts {
		if m.Type == "devfs" {
			m.Options = []string{"ruleset=0"}
			c.Spec().Config.Mounts[i] = m
			return nil
		}
	}
	return nil
}

func (c *container) specAddContainerConfigDevices(enableDeviceOwnershipFromSecurityContext bool) error {
	return nil
}

func (c *container) specInjectCDIDevices() error {
	return nil
}

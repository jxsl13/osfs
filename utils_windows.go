package osfs

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func getNamedSecurityDescriptor(name string) (sd *windows.SECURITY_DESCRIPTOR, err error) {
	return windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
}

func enablePrivilege(priv string) error {
	return requestPrivilege(priv, true)
}

func disablePrivilege(priv string) error {
	return requestPrivilege(priv, false)
}

func requestPrivilege(priv string, elevated bool) error {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &t); err != nil {
		return err
	}

	var luid windows.LUID

	err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(priv), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup privilege value: %w", err)
	}

	attr := uint32(0)
	if elevated {
		attr = windows.SE_PRIVILEGE_ENABLED
	}

	ap := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: attr,
			},
		},
	}

	if err := windows.AdjustTokenPrivileges(t, false, &ap, 0, nil, nil); err != nil {
		return fmt.Errorf("failed to adjust token privileged: %w", err)
	}

	return nil
}

func LookupAccount(sid string) (account string, domain string, accType uint32, err error) {
	ssid, err := windows.StringToSid(sid)
	if err != nil {
		return "", "", 0, err
	}

	return ssid.LookupAccount("")
}

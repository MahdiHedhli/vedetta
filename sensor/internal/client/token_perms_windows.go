//go:build windows

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// The directory is born with its final owner and protected DACL. Creating it
	// permissively and repairing it later is unsafe: a pre-creator can retain an
	// already-open ADD_FILE/DELETE_CHILD handle even after an ACL replacement.
	secureDirectorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	fileFullControl     = windows.ACCESS_MASK(0x001F01FF)
)

// ensureSecureDirectory atomically creates a missing token directory with the final
// descriptor, or verifies an existing directory already has exactly that invariant.
// It deliberately never repairs an unexpected existing directory in place. That
// fail-closed policy prevents junction traversal and stale-handle races.
func ensureSecureDirectory(path string) error {
	if path == "" {
		return fmt.Errorf("secure directory path is empty")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("secure directory path %s is not a directory", path)
		}
		if err := verifySecurePath(path, true); err != nil {
			return fmt.Errorf("existing token directory %s is not the trusted Vedetta directory; remove it after closing any handles or reboot, then retry: %w", path, err)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("inspect token directory %s: %w", path, err)
	}

	parent := filepath.Dir(path)
	if parent == path {
		return fmt.Errorf("refusing to create filesystem root as token directory: %s", path)
	}
	parentHandle, err := openNonReparsePath(parent, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("token directory parent %s is unavailable or a reparse point: %w", parent, err)
	}
	_ = windows.CloseHandle(parentHandle)

	sd, err := windows.SecurityDescriptorFromString(secureDirectorySDDL)
	if err != nil {
		return fmt.Errorf("build token directory security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode token directory path: %w", err)
	}
	err = windows.CreateDirectory(pathPtr, &sa)
	runtime.KeepAlive(sd)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return fmt.Errorf("create protected token directory %s: %w", path, err)
	}
	// ERROR_ALREADY_EXISTS can mean an attacker won the creation race. Exact
	// verification distinguishes our object without ever mutating theirs.
	if err := verifySecurePath(path, true); err != nil {
		return fmt.Errorf("new token directory %s failed exact owner/DACL verification: %w", path, err)
	}
	return nil
}

// securePath applies the exact file descriptor to a non-reparse token/temp file.
// Directories are created by ensureSecureDirectory and are verification-only here:
// repairing an unexpected directory would preserve hostile open handles.
func securePath(path string, isDir bool) error {
	if isDir {
		return verifySecurePath(path, true)
	}

	adminSID, systemSID, err := vedettaSIDs()
	if err != nil {
		return err
	}
	restorePrivilege, err := enableTakeOwnershipPrivilege()
	if err != nil {
		return fmt.Errorf("enable SeTakeOwnershipPrivilege for %s: %w", path, err)
	}
	// Excluding FILE_SHARE_DELETE keeps the name bound to this object until both the
	// ownership and DACL changes complete. OPEN_REPARSE_POINT makes the final path
	// component inspectable rather than following a symlink/junction.
	ownerHandle, err := openNonReparsePath(path, windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		_ = restorePrivilege()
		return fmt.Errorf("open token path for ownership %s: %w", path, err)
	}
	defer windows.CloseHandle(ownerHandle)
	if err := windows.SetSecurityInfo(ownerHandle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, adminSID, nil, nil, nil); err != nil {
		_ = restorePrivilege()
		return fmt.Errorf("take ownership of %s: %w", path, err)
	}
	if err := restorePrivilege(); err != nil {
		return fmt.Errorf("restore token privileges after securing %s: %w", path, err)
	}

	dacl, err := vedettaDACL(adminSID, systemSID, false)
	if err != nil {
		return fmt.Errorf("build protected DACL for %s: %w", path, err)
	}
	daclHandle, err := openNonReparsePath(path,
		windows.WRITE_DAC|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("reopen owned token path %s for DACL replacement: %w", path, err)
	}
	defer windows.CloseHandle(daclHandle)
	if err := windows.SetSecurityInfo(daclHandle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("replace protected DACL for %s: %w", path, err)
	}
	if err := verifySecureHandle(daclHandle, false); err != nil {
		return fmt.Errorf("verify protected token path %s: %w", path, err)
	}
	return nil
}

func openNonReparsePath(path string, access uint32) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := windows.CreateFile(pathPtr, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, fmt.Errorf("refusing reparse point")
	}
	return handle, nil
}

func verifySecurePath(path string, isDir bool) error {
	handle, err := openNonReparsePath(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return verifySecureHandle(handle, isDir)
}

func verifySecureHandle(handle windows.Handle, isDir bool) error {
	adminSID, systemSID, err := vedettaSIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if !windows.EqualSid(owner, adminSID) {
		return fmt.Errorf("owner is %s, want BUILTIN\\Administrators", owner.String())
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("DACL inheritance is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount != 2 {
		if dacl == nil {
			return fmt.Errorf("DACL is nil")
		}
		return fmt.Errorf("DACL has %d ACEs, want exactly 2", dacl.AceCount)
	}
	expectedFlags := uint8(windows.NO_INHERITANCE)
	if isDir {
		expectedFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	foundSystem, foundAdmins := false, false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != expectedFlags || ace.Mask != fileFullControl {
			return fmt.Errorf("ACE %d is not exact allow/full-control/inheritance policy", i)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case windows.EqualSid(sid, systemSID):
			if foundSystem {
				return fmt.Errorf("duplicate LocalSystem ACE")
			}
			foundSystem = true
		case windows.EqualSid(sid, adminSID):
			if foundAdmins {
				return fmt.Errorf("duplicate Administrators ACE")
			}
			foundAdmins = true
		default:
			return fmt.Errorf("unexpected DACL trustee %s", sid.String())
		}
	}
	if !foundSystem || !foundAdmins {
		return fmt.Errorf("DACL is missing LocalSystem or Administrators")
	}
	return nil
}

func vedettaSIDs() (adminSID, systemSID *windows.SID, err error) {
	adminSID, err = windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return nil, nil, fmt.Errorf("parse Administrators SID: %w", err)
	}
	systemSID, err = windows.StringToSid("S-1-5-18")
	if err != nil {
		return nil, nil, fmt.Errorf("parse LocalSystem SID: %w", err)
	}
	return adminSID, systemSID, nil
}

func vedettaDACL(adminSID, systemSID *windows.SID, isDir bool) (*windows.ACL, error) {
	inheritance := uint32(windows.NO_INHERITANCE)
	if isDir {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	var pinner runtime.Pinner
	pinner.Pin(adminSID)
	pinner.Pin(systemSID)
	defer pinner.Unpin()
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: fileFullControl,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
		{
			AccessPermissions: fileFullControl,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(adminSID),
			},
		},
	}
	return windows.ACLFromEntries(entries, nil)
}

// enableTakeOwnershipPrivilege enables the one privilege needed for a token file
// created by an older trusted install. The returned closure restores the process
// token to its previous state.
func enableTakeOwnershipPrivilege() (func() error, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString("SeTakeOwnershipPrivilege")
	if err != nil {
		_ = token.Close()
		return nil, err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		_ = token.Close()
		return nil, err
	}
	desired := windows.Tokenprivileges{PrivilegeCount: 1}
	desired.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	var previous windows.Tokenprivileges
	var previousLen uint32
	if err := windows.AdjustTokenPrivileges(token, false, &desired,
		uint32(unsafe.Sizeof(previous)), &previous, &previousLen); err != nil {
		_ = token.Close()
		return nil, err
	}
	restored := false
	return func() error {
		if restored {
			return nil
		}
		restored = true
		err := windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
		closeErr := token.Close()
		if err != nil {
			return err
		}
		return closeErr
	}, nil
}

// NTFS security is not represented by Go's synthesized permission bits. Always
// verify/re-apply the exact file owner and DACL before reading an existing token.
func hasInsecurePerms(os.FileMode) bool { return true }

//go:build windows

package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tokenReplaceAttempts = 24
	tokenReplaceMaxDelay = 40 * time.Millisecond
)

// fileRenameInfo mirrors the variable-length FILE_RENAME_INFO layout used with
// SetFileInformationByHandle(FileRenameInfoEx). Go supplies the native pointer
// alignment between Flags and RootDirectory; unsafe.Offsetof(FileName) is used
// below instead of assuming the 32-bit or 64-bit header size.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

func replaceTokenFile(from, to string) error {
	if err := validateNoReparseAncestry(filepath.Dir(from)); err != nil {
		return fmt.Errorf("validate sensor token rename source ancestry: %w", err)
	}
	if err := validateNoReparseAncestry(filepath.Dir(to)); err != nil {
		return fmt.Errorf("validate sensor token rename target ancestry: %w", err)
	}
	// Refuse a directory, symlink/reparse point, or other special target before
	// requesting any rename. The protected token directory prevents an
	// unprivileged name swap after this check.
	if info, err := os.Lstat(to); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace non-regular sensor token target %s", to)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	renameBuffer, err := buildTokenRenameInfo(to)
	if err != nil {
		return err
	}
	sourceHandle, err := openTokenRenameSourceWithRetry(from)
	if err != nil {
		return err
	}

	// FileRenameInfoEx with POSIX semantics is the Windows primitive that permits
	// an atomic replacement while readers that opted into FILE_SHARE_DELETE keep
	// handles to the old file. New opens resolve to the replacement immediately;
	// existing readers finish against the old object. Ordinary MoveFileEx cannot
	// make that guarantee and fails while the destination has open handles.
	renameErr := retryTokenReplace(func() error {
		return windows.SetFileInformationByHandle(
			sourceHandle,
			windows.FileRenameInfoEx,
			&renameBuffer[0],
			uint32(len(renameBuffer)),
		)
	})
	if renameErr == nil {
		// The rename is already committed. A CloseHandle failure must not be
		// reported as a failed persistence operation and desynchronize memory
		// from the successfully replaced on-disk credential.
		_ = windows.CloseHandle(sourceHandle)
		return nil
	}
	if !renameInfoExUnsupported(renameErr) {
		_ = windows.CloseHandle(sourceHandle)
		return renameErr
	}

	// FileRenameInfoEx/POSIX semantics are unavailable on some older or non-NTFS
	// filesystems. Close our DELETE-capable source handle before falling back:
	// MoveFileEx uses ordinary rename semantics and cannot move an open source.
	if err := windows.CloseHandle(sourceHandle); err != nil {
		return fmt.Errorf("close token rename source before compatibility fallback: %w", err)
	}
	return moveTokenFileWithRetry(from, to)
}

func buildTokenRenameInfo(target string) ([]byte, error) {
	absoluteTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute sensor token target: %w", err)
	}
	name, err := windows.UTF16FromString(absoluteTarget)
	if err != nil {
		return nil, fmt.Errorf("encode sensor token target: %w", err)
	}
	if len(name) <= 1 {
		return nil, fmt.Errorf("sensor token target is empty")
	}

	var layout fileRenameInfo
	nameOffset := int(unsafe.Offsetof(layout.FileName))
	// Keep the terminating NUL in the allocated buffer even though the API's
	// FileNameLength deliberately excludes it. Allocate at least sizeof(struct)
	// so the typed header access also remains within the backing object.
	bufferSize := nameOffset + len(name)*2
	if minimum := int(unsafe.Sizeof(layout)); bufferSize < minimum {
		bufferSize = minimum
	}
	buffer := make([]byte, bufferSize)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	info.RootDirectory = 0
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return buffer, nil
}

func openTokenRenameSource(path string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.DELETE|windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
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
		return windows.InvalidHandle, fmt.Errorf("refusing reparse-point token rename source")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, fmt.Errorf("token rename source is not a regular file")
	}
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	if fileType != windows.FILE_TYPE_DISK {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, fmt.Errorf("token rename source is not a disk file")
	}
	return handle, nil
}

func openTokenRenameSourceWithRetry(path string) (windows.Handle, error) {
	delay := time.Millisecond
	var lastErr error
	for attempt := 0; attempt < tokenReplaceAttempts; attempt++ {
		handle, err := openTokenRenameSource(path)
		if err == nil {
			return handle, nil
		}
		lastErr = err
		if !tokenReplaceTransient(err) {
			return windows.InvalidHandle, err
		}
		if attempt+1 < tokenReplaceAttempts {
			time.Sleep(delay)
			if delay < tokenReplaceMaxDelay {
				delay *= 2
				if delay > tokenReplaceMaxDelay {
					delay = tokenReplaceMaxDelay
				}
			}
		}
	}
	return windows.InvalidHandle, lastErr
}

func retryTokenReplace(operation func() error) error {
	delay := time.Millisecond
	var lastErr error
	for attempt := 0; attempt < tokenReplaceAttempts; attempt++ {
		lastErr = operation()
		if lastErr == nil {
			return nil
		}
		if renameInfoExUnsupported(lastErr) || !tokenReplaceTransient(lastErr) {
			return lastErr
		}
		if attempt+1 < tokenReplaceAttempts {
			time.Sleep(delay)
			if delay < tokenReplaceMaxDelay {
				delay *= 2
				if delay > tokenReplaceMaxDelay {
					delay = tokenReplaceMaxDelay
				}
			}
		}
	}
	return lastErr
}

func moveTokenFileWithRetry(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return retryTokenReplace(func() error {
		return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	})
}

func tokenReplaceTransient(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func renameInfoExUnsupported(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, windows.ERROR_CALL_NOT_IMPLEMENTED) ||
		errors.Is(err, windows.ERROR_INVALID_LEVEL)
}

// The replacement file is flushed before replaceTokenFile is called, and the
// DELETE-capable rename handle is opened with FILE_FLAG_WRITE_THROUGH. Windows
// does not expose a portable directory fsync through os.File, so there is no
// additional directory operation to perform here.
func syncTokenDirectory(string) error { return nil }

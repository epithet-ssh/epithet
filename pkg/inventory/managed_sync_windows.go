package inventory

// Windows does not support fsync of directory handles through os.File.
func syncManagedDir(string) error { return nil }

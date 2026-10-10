package writpolicy

// defaultExtensions returns the default SSH certificate extensions
func defaultExtensions() map[string]string {
	return map[string]string{
		"permit-pty":              "",
		"permit-agent-forwarding": "",
		"permit-user-rc":          "",
	}
}

// defaultExpiration returns the default certificate expiration duration
func defaultExpiration() string {
	return "5m"
}

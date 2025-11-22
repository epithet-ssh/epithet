// CUE format policy configuration
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: {
	issuer: "https://accounts.google.com"
	audience: "test-client-id"
}

users: {
	"a@example.com": ["wheel"]
	"b@example.com": ["dev"]
}

defaults: {
	allow: {
		root: ["wheel"]
	}
	expiration: "5m"
	extensions: {
		"permit-pty": ""
		"permit-agent-forwarding": ""
		"permit-user-rc": ""
	}
}

hosts: {
	m0001: {}
	v0003: {
		allow: {
			arch: ["dev"]
		}
		expiration: "1h"
	}
}

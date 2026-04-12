REPO_ROOT ?= ../..
ARCH      ?= amd64
ABI       ?= FreeBSD:15:amd64
PREFIX    ?= /usr/local

.if !defined(VERSION)
VERSION != cd $(REPO_ROOT) && git describe --tags --always 2>/dev/null || echo "0.0.0-dev"
.endif

STAGEDIR  = _stage
BUILDDIR  = _build
MANIFEST  = $(BUILDDIR)/+MANIFEST

BINARY    = $(BUILDDIR)/epithet
PKG_FILE  = epithet-$(VERSION).pkg

.PHONY: help package clean

help:
	@echo "FreeBSD package builder for epithet"
	@echo ""
	@echo "Targets:"
	@echo "  make package            Build epithet from source and create .pkg"
	@echo "  make clean              Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)"
	@echo "  ARCH=$(ARCH)"
	@echo "  ABI=$(ABI)"
	@echo ""
	@echo "Requires: go (pkg install go)"

package: $(PKG_FILE)

$(BINARY):
	@echo "==> Building epithet $(VERSION) for freebsd/$(ARCH)"
	@mkdir -p $(BUILDDIR)
	cd $(REPO_ROOT) && CGO_ENABLED=0 GOOS=freebsd GOARCH=$(ARCH) go build \
		-ldflags "-s -w -X main.version=$(VERSION)" \
		-o contrib/freebsd/$(BINARY) ./cmd/epithet

$(MANIFEST): +MANIFEST
	@mkdir -p $(BUILDDIR)
	sed -e 's/%%VERSION%%/$(VERSION)/g' -e 's/%%ABI%%/$(ABI)/g' +MANIFEST > $(MANIFEST)

$(STAGEDIR): $(BINARY)
	@echo "==> Staging files"
	@rm -rf $(STAGEDIR)
	install -d $(STAGEDIR)/$(PREFIX)/bin
	install -m 0755 $(BINARY) $(STAGEDIR)/$(PREFIX)/bin/epithet
	install -d $(STAGEDIR)/$(PREFIX)/etc/rc.d
	install -m 0555 rc.d/epithet_server $(STAGEDIR)/$(PREFIX)/etc/rc.d/epithet_server
	install -d $(STAGEDIR)/$(PREFIX)/etc/epithet
	install -m 0644 server.yaml.sample $(STAGEDIR)/$(PREFIX)/etc/epithet/server.yaml.sample

$(PKG_FILE): $(STAGEDIR) $(MANIFEST)
	@echo "==> Creating package $(PKG_FILE)"
	pkg create -M $(MANIFEST) -r $(STAGEDIR) -p plist -o .
	@echo "==> Built $(PKG_FILE)"

clean:
	rm -rf $(STAGEDIR) $(BUILDDIR) epithet-*.pkg

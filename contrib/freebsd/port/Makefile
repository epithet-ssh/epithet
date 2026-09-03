PORTNAME=	epithet
DISTVERSIONPREFIX=	v
DISTVERSION=	0.23.0
CATEGORIES=	security

MAINTAINER=	brianm@apache.org
COMMENT=	SSH certificate authorization and host enrollment
WWW=		https://epithet.dev/

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE-2.0.txt

USES=		go:1.25+,modules
GO_MODULE=	github.com/epithet-ssh/epithet
GO_TARGET=	./cmd/epithet
GO_LDFLAGS=	-X main.version=${DISTVERSION}
CGO_ENABLED=	0

PLIST_FILES=	bin/epithet

.include <bsd.port.mk>

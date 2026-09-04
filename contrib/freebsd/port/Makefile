PORTNAME=	epithet
DISTVERSIONPREFIX=	v
DISTVERSION=	0.23.1
PORTREVISION=	3
CATEGORIES=	security

MAINTAINER=	brianm@apache.org
COMMENT=	SSH certificate authorization and host enrollment
WWW=		https://epithet.dev/

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE-2.0.txt

USES=		go:1.25+,modules
USE_RC_SUBR=	epithet_server epithet_ca epithet_policy
GO_MODULE=	github.com/epithet-ssh/epithet
GO_TARGET=	./cmd/epithet
GO_LDFLAGS=	-X main.version=${DISTVERSION}
CGO_ENABLED=	0

USERS=		epithet
GROUPS=		epithet
UID_FILES=	${FILESDIR}/UIDs ${PORTSDIR}/UIDs
GID_FILES=	${FILESDIR}/GIDs ${PORTSDIR}/GIDs

post-install:
	${MKDIR} ${STAGEDIR}${ETCDIR}
	${INSTALL_DATA} ${FILESDIR}/server.yaml.sample \
		${STAGEDIR}${ETCDIR}/server.yaml.sample

.include <bsd.port.mk>

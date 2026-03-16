include $(TOPDIR)/rules.mk

PKG_NAME:=opera-proxy
PKG_VERSION:=1.15.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_PROTO:=none
PKG_MIRROR_HASH:=skip

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/opera-proxy
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Opera VPN/Proxy service
  URL:=https://github.com/Alexey71/opera-proxy
  DEPENDS:=+ca-bundle
endef

define Build/Compile
	( \
		cd $(PKG_BUILD_DIR); \
		export GO111MODULE=on; \
		export GOPROXY=https://proxy.golang.org; \
		export GOOS=linux; \
		export GOARCH=arm64; \
		export CGO_ENABLED=0; \
		go mod tidy; \
		go build -o opera-proxy . ; \
	)
endef

define Package/opera-proxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/opera-proxy $(1)/usr/bin/
endef

$(eval $(call BuildPackage,opera-proxy))

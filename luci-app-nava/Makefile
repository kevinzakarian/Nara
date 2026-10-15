include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-nava
PKG_VERSION:=1.0.0
PKG_RELEASE:=30
PKG_LICENSE:=MIT

LUCI_TITLE:=NARA - subscription connection manager for sing-box
LUCI_DEPENDS:=+python3 +curl +ca-bundle +kmod-tun +kmod-nft-tproxy +kmod-nft-queue +ip-full +firewall4 +conntrack +rpcd
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/conffiles
/etc/nava/
endef

include $(TOPDIR)/feeds/luci/luci.mk

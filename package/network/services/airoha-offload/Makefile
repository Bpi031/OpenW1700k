# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
#
# OpenWrt package definition for the eBPF/TC NPU offload datapath
# and the userspace synchronization daemon.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/bpf.mk

PKG_NAME:=airoha-offload
PKG_RELEASE:=4

PKG_BUILD_DEPENDS:=bpf-headers bpftool/host

include $(INCLUDE_DIR)/package.mk

define Package/airoha-offload
  SECTION:=net
  CATEGORY:=Network
  TITLE:=eBPF/TC NPU Offloading & Sync Daemon for Airoha AN7581
  DEPENDS:=+kmod-airoha-eth +libbpf +libnetfilter-conntrack +libmnl \
           +ip-full +kmod-mt76-connac +bpftool $(BPF_DEPENDS)
endef

define Package/airoha-offload/description
  Selective eBPF-driven hardware flow offloading for the Airoha AN7581
  SoC (Gemtek MXF-W1700K). Uses TC ingress to identify bulk flows and
  mark them for NPU acceleration while preserving CPU-based SQM/CAKE
  for latency-sensitive traffic.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	# Generate vmlinux.h from the kernel's BTF data
	$(STAGING_DIR_HOST)/usr/sbin/bpftool btf dump \
		file $(LINUX_DIR)/vmlinux format c \
		> $(PKG_BUILD_DIR)/vmlinux.h

	# Compile eBPF datapath with vmlinux.h (cannot use CompileBPF
	# which adds kernel headers that conflict with vmlinux.h)
	$(CLANG) -g -O2 \
		-target $(BPF_TARGET) \
		-D__TARGET_ARCH_$(BPF_KARCH) \
		-I$(PKG_BUILD_DIR) \
		-I$(BPF_HEADERS_DIR)/tools/lib \
		-Wall -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-fno-stack-protector \
		-c $(PKG_BUILD_DIR)/airoha_hybrid_offload.c \
		-o $(PKG_BUILD_DIR)/airoha_hybrid_offload.o
	$(LLVM_STRIP) --strip-debug $(PKG_BUILD_DIR)/airoha_hybrid_offload.o

	# Compile userspace sync daemon for target
	$(TARGET_CC) $(TARGET_CFLAGS) \
		-o $(PKG_BUILD_DIR)/airoha-sync-daemon \
		$(PKG_BUILD_DIR)/airoha-sync-daemon.c \
		$(TARGET_LDFLAGS) -lbpf -lnetfilter_conntrack -lmnl
endef

define Package/airoha-offload/install
	$(INSTALL_DIR) $(1)/lib/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/airoha_hybrid_offload.o $(1)/lib/bpf/airoha_offload.o

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/airoha-sync-daemon $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/airoha-ebpf.init $(1)/etc/init.d/airoha-ebpf

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-disable-native-hwnat $(1)/etc/uci-defaults/99-disable-native-hwnat
	$(INSTALL_BIN) ./files/11-airoha-10g-tuning $(1)/etc/uci-defaults/11-airoha-10g-tuning
endef

$(eval $(call BuildPackage,airoha-offload))

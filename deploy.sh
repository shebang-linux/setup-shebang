#!/bin/bash

# Boring stuff should probably do now
ln -sf /usr/share/zoneinfo/"$REGION_CITY" /etc/localtime
hwclock --systohc

# Localization
echo -e "CHARSET=UTF-8
LANG=en_GB.UTF-8
LC_COLLATE=C
XKB_DEFAULT_LAYOUT=$KEYMAP" >/etc/environment
echo "en_GB.UTF-8 UTF-8" >/etc/locale.gen
locale-gen
echo -e "FONT_MAP=8859-2
KEYMAP=$KEYMAP" >/etc/vconsole.conf

# Host
echo -e "$HOST" >/etc/hostname
mkdir -p /etc/conf.d
echo -e "hostname=$HOST" >/etc/conf.d/hostname

# User
useradd -m -G users,audio,video,input -s /usr/bin/bash $USERNAME
yes "$ROOT_PASSWORD" | passwd $USERNAME

# Root
yes "$ROOT_PASSWORD" | passwd

# Pacman
curl -so /tmp/fontconfig-2:2.16.2-1-x86_64.pkg.tar.zst https://archive.artixlinux.org/packages/f/fontconfig/fontconfig-2%3A2.16.2-1-x86_64.pkg.tar.zst
pacman -U --noconfirm /tmp/fontconfig-2:2.16.2-1-x86_64.pkg.tar.zst

echo -e '# Default mirrors
Server = https://mirrors.rit.edu/artixlinux/$repo/os/$arch
Server = https://mirrors.dotsrc.org/artix-linux/repos/$repo/os/$arch' >/etc/pacman.d/mirrorlist
sed -i -e '/^HoldPkg/a XferCommand = /sbin/curl -fSL --proto=https --tlsv1.3 --progress-bar -o %o %u' /etc/pacman.conf
sed -i -e '/#DisableSandbox/a DisableDownloadTimeout' /etc/pacman.conf
sed -i -e 's/^SigLevel.*/SigLevel = Required DatabaseOptional TrustedOnly/g' /etc/pacman.conf
sed -i -e s"/\#VerbosePkgLists/VerbosePkgLists/"g /etc/pacman.conf
sed -i -e s"/\#ParallelDownloads.*/ParallelDownloads = 3/"g /etc/pacman.conf
sed -i -e s"/\#CheckSpace/CheckSpace/"g /etc/pacman.conf
sed -i -e s"/\#CacheDir.*/CacheDir = \/tmp\//"g /etc/pacman.conf
sed -i -e s"/\#LogFile.*/LogFile = \/dev\/null/"g /etc/pacman.conf
sed -i -e s"/\#CleanMethod.*/CleanMethod = KeepCurrent/"g /etc/pacman.conf
sed -i -e 's/#IgnorePkg.*/IgnorePkg = sudo fontconfig/' /etc/pacman.conf
sed -i -e s"/\#NoExtract.*/NoExtract = usr\/share\/doc\/* usr\/share\/gtk-doc\/* usr\/share\/help\/* usr\/share\/info\/* usr\/share\/man\/*/"g /etc/pacman.conf
sed -i -e s'/\/usr\/bin/\/sbin/'g /etc/makepkg.conf
sed -i -e s'/curl -qgb.*/curl -fSL --proto=https --tlsv1.3 --progress-bar -o %o %u'\''/'g /etc/makepkg.conf
sed -i -e s'/^CHOST.*/CHOST="x86_64-linux-musl"/'g /etc/makepkg.conf
sed -i -e '/^CFLAGS=/,/"/c\CFLAGS="-march=native -mtune=native -Os -flto -Wl,-flto -pipe \\\n\t-fomit-frame-pointer -momit-leaf-frame-pointer \\\n\t-fno-plt -fno-semantic-interposition \\\n\t-ffunction-sections -fdata-sections"' /etc/makepkg.conf
sed -i -e s'/^CXXFLAGS=.*/CXXFLAGS="$CFLAGS"/'g /etc/makepkg.conf
sed -i -e '/^LDFLAGS=/,/"/c\LDFLAGS="-Os -Wl,-flto -Wl,--sort-common -Wl,--as-needed -Wl,--gc-sections -Wl,-z,now -s"' /etc/makepkg.conf
sed -i -e s'/^DEBUG_CFLAGS=.*/DEBUG_CFLAGS="-g0 -s"/'g /etc/makepkg.conf
sed -i -e "s/-j.*/-j$(expr $(nproc) - 1) -l$(nproc)\"/;s/^#MAKEFLAGS/MAKEFLAGS/;s/^#RUSTFLAGS/RUSTFLAGS/" /etc/makepkg.conf
sed -i -e "s|BUILDENV.*|BUILDENV=(!distcc !color !ccache !check !sign)|g" /etc/makepkg.conf
sed -i -e "s/.*BUILDDIR.*/BUILDDIR=\/var\/lib\/pacman\/sources/g" /etc/makepkg.conf
sed -i -e "s|OPTIONS=(.*|OPTIONS=(strip !docs !libtool !staticlibs emptydirs zipman purge !debug lto)|g" /etc/makepkg.conf
sed -i -e "s/xz.*/xz -c -z -q - --threads=$(nproc))/;s/^#COMPRESSXZ/COMPRESSXZ/;s/zstd.*/zstd -c -z -q - --threads=$(nproc))/;s/^#COMPRESSZST/COMPRESSZST/;s/lz4.*/lz4 -q --best)/;s/^#COMPRESSLZ4/COMPRESSLZ4/" /etc/makepkg.conf
sed -i -e "s/PKGEXT.*/PKGEXT='.pkg.tar.lz4'/g" /etc/makepkg.conf
sed -i -e "s/.*PACMAN_AUTH.*/PACMAN_AUTH=(doas)/g" /etc/makepkg.conf

cp -rfd /etc/pacman.conf /etc/pacman.conf.bak

echo -e "[universe]
Server = https://universe.artixlinux.org/\$arch
Server = https://mirror1.artixlinux.org/universe/\$arch
Server = https://mirror.pascalpuffke.de/artix-universe/\$arch
Server = https://mirrors.qontinuum.space/artixlinux-universe/\$arch
Server = https://mirror1.cl.netactuate.com/artix/universe/\$arch
Server = https://ftp.crifo.org/artix-universe/\$arch
Server = https://artix.sakamoto.pl/universe/\$arch
# TOR
Server = http://rrtovkpcaxl6s2ommj5tigyxamzxaknasd74ecb5t5cdfnkodirjnwyd.onion/artixlinux/\$arch
" >>/etc/pacman.conf

pacman -Sy --needed --noconfirm --disable-download-timeout artix-keyring artix-archlinux-support

echo -e "
# Arch
[extra]
Include = /etc/pacman.d/mirrorlist-arch

#[community]
#Include = /etc/pacman.d/mirrorlist-arch

#[multilib]
#Include = /etc/pacman.d/mirrorlist-arch
" >>/etc/pacman.conf

pacman -Sy && pacman-key --init && pacman-key --populate archlinux
pacman -Sy --needed --noconfirm --disable-download-timeout alsa-utils backlight-$INIT bluez-$INIT dbus-broker doas egl-gbm egl-x11 egl-wayland fwupd gtk-engines gtk-engine-murrine haveged-$INIT iw jitterentropy libva-mesa-driver macchanger mesa mesa-vdpau msr-tools openbox pipewire pipewire-alsa pipewire-pulse rsync scx-scheds tmux tor-$INIT torsocks unzip usbutils vim vulkan-mesa-layers wayland wget wireplumber wpa_supplicant xdg-desktop-portal-gtk xdg-utils xdg-user-dirs xlibre xorg-xinit xterm

mkdir -p /etc/pacman.d/hooks

echo -e "[Trigger]
Operation = Install
Operation = Remove
Operation = Upgrade
Type = Package
Target = *

[Action]
When = PostTransaction
Exec = /sbin/sh -c '[ \$DISPLAY ] && XAUTHORITY=/home/$USERNAME/.Xauthority setxkbmap $KEYMAP'" >/etc/pacman.d/hooks/set-keyboard-layout-back-to-normal.hook

echo -e "SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
Sandbox 1
HardwareAccel 1
UseEntryGuards 1
EnforceDistinctSubnets 1
StrictNodes 0" >>/etc/tor/torrc

# Pull shebang-dotfiles
cd /tmp
wget -qO shebang-ui-theme.zip https://github.com/shebang-linux/shebang-ui-theme/archive/refs/heads/main.zip && unzip shebang-ui-theme.zip && mv shebang-ui-theme-main shebang-ui-theme
cp -rfd shebang-ui-theme/* /usr/share/themes
rm -rfd /usr/share/backgrounds
mkdir -p /usr/share/backgrounds
wget -qO config.zip https://github.com/shebang-linux/shebang-dotfiles/archive/refs/heads/main.zip && unzip config.zip && mv shebang-dotfiles-main .config
rm -rfd *.zip
rm -rfd /home/$USERNAME/*
rm -rfd /etc/skel/*
rm -rfd /root/*
rm -rfd /home/$USERNAME/.*
rm -rfd /etc/skel/.*
rm -rfd /root/.*
rmdir -p /home/$USERNAME/*
rmdir -p /etc/skel/*
rmdir -p /root/*
mkdir -p /home/$USERNAME/.config
mkdir -p /etc/skel/.config
mkdir -p /root/.config
mkdir -p /home/$USERNAME/.local
mkdir -p /etc/skel/.local
mkdir -p /root/.local
mkdir -p /etc/skel/backup
cp -rfd .config/.gtkrc-2.0 /home/$USERNAME/.gtkrc-2.0
cp -rfd .config/.fonts.conf /home/$USERNAME
cp -rfd .config/.gtk-bookmarks /home/$USERNAME
cp -rfd .config/.vimrc /home/$USERNAME
cp -rfd .config/.xinitrc /home/$USERNAME
cp -rfd .config/.Xresources /home/$USERNAME
cp -rfd .config/.nanorc /home/$USERNAME
cp -rfd .config/.mkshrc /home/$USERNAME
cp -rfd .config/.profile /home/$USERNAME
cp -rfd .config/.bashrc /home/$USERNAME
cp -rfd .config/.tmux.conf /home/$USERNAME
cp -rfd .config/.gtkrc-2.0 /etc/skel/.gtkrc-2.0
cp -rfd .config/.fonts.conf /etc/skel
cp -rfd .config/.gtk-bookmarks /etc/skel
cp -rfd .config/.vimrc /etc/skel
cp -rfd .config/.xinitrc /etc/skel
cp -rfd .config/.Xresources /etc/skel
cp -rfd .config/.nanorc /etc/skel
cp -rfd .config/.mkshrc /etc/skel
cp -rfd .config/.profile /etc/skel
cp -rfd .config/.bashrc /etc/skel
cp -rfd .config/.tmux.conf /etc/skel
mv .config/.gtkrc-2.0 /root/.gtkrc-2.0
mv .config/.fonts.conf /root
mv .config/.gtk-bookmarks /root
mv .config/.vimrc /root
mv .config/.xinitrc /root
mv .config/.Xresources /root
mv .config/.nanorc /root
mv .config/.mkshrc /root
mv .config/.profile /root
mv .config/.bashrc /root
mv .config/.tmux.conf /root
mv .config/wallpaper*.png /usr/share/backgrounds
cp -rfd .config/.newsboat /home/$USERNAME/.newsboat
cp -rfd .config/.newsboat /etc/skel/.newsboat
cp -rfd .config/.newsboat /root/.newsboat
cp -rfd .config/.irssi /home/$USERNAME/.irssi
cp -rfd .config/.irssi /etc/skel/.irssi
cp -rfd .config/.irssi /root/.irssi
cp -rfd .config/.local/* /home/$USERNAME/.local
cp -rfd .config/.local/* /etc/skel/.local
cp -rfd .config/.local/* /root/.local
cp -rfd .config/* /home/$USERNAME/.config
cp -rfd .config/* /etc/skel/.config
cp -rfd .config/* /root/.config
mkdir -p /var/cache/libx11/compose
mkdir -p /home/$USERNAME/.compose-cache
touch /home/$USERNAME/.XCompose
chown -hR $USERNAME:$USERNAME /usr/share/backgrounds
chown -hR $USERNAME:$USERNAME /usr/share/themes/Shebang*
chown -hR $USERNAME:$USERNAME /home/$USERNAME/.*
chown -hR $USERNAME:$USERNAME /home/$USERNAME/*
find /home/$USERNAME/.config/ | grep '\shebang' | xargs rm -f
find /root/.config/ | grep '\shebang' | xargs rm -f
rm -rfd .config*

# Other stuff should do
wget -qO /etc/preload.conf https://raw.githubusercontent.com/shebang-linux/setup-shebang/main/preload/preload.conf
wget -qO /sbin/preload https://raw.githubusercontent.com/shebang-linux/setup-shebang/main/preload/preload
chmod +x /sbin/preload
wget -qO /etc/prelockd.conf https://raw.githubusercontent.com/shebang-linux/setup-shebang/main/prelockd/prelockd.conf
wget -qO /sbin/prelockd https://raw.githubusercontent.com/hakavlad/prelockd/refs/heads/master/prelockd
chmod +x /sbin/prelockd
wget -qO /etc/hosts https://github.com/StevenBlack/hosts/raw/refs/heads/master/alternates/fakenews-gambling-porn-social/hosts && sed -i -e 's/#.*0.0.0.0/0.0.0.0/g' /etc/hosts

echo -e "permit nopass :$USERNAME" >/etc/doas.conf

sed -i -e "s/replaceme/$KEYMAP/" /home/$USERNAME/.config/openbox/autostart
sed -i -e "s/replaceme/$KEYMAP/" /etc/skel/.config/openbox/autostart
sed -i -e "s/replaceme/$KEYMAP/" /root/.config/openbox/autostart

sed -i -e 's/#HandleLidSwitch=.*/HandleLidSwitch=suspend/' /etc/elogind/logind.conf
sed -i -e 's/#HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=suspend/' /etc/elogind/logind.conf
sed -i -e 's/#HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' /etc/elogind/logind.conf
sed -i -e 's/#HandlePowerKeyLongPress=.*/HandlePowerKeyLongPress=reboot/' /etc/elogind/logind.conf

echo -e 'Section "ServerFlags"
    Option "GlxVisuals" "minimal"
    Option "Log" "flush"
EndSection

Section "Device"
    Identifier "Device0"
    Option "PageFlip" "false"
    Option "TearFree" "true"
    Option "DynamicPMMSupport" "true"
    Option "PowerSave" "true"
EndSection

Section "Extensions"
    Option "Damage" "off"
    Option "DAMAGE" "off"
EndSection' >/etc/X11/xorg.conf.d/10-xorg.conf

echo -e "CPU_LIMIT=0
GPU_USE_SYNC_OBJECTS=1
SHARED_MEMORY=1
MALLOC_CONF=background_thread:true
MALLOC_CHECK=0
MALLOC_TRACE=0
LD_DEBUG_OUTPUT=0
LD_BIND_NOW=1
LLVM_DEBUG=0
PP_DEBUG=0
MESA_DEBUG=0
LIBGL_DEBUG=0
LIBGL_NO_DRAWARRAYS=1
LIBGL_THROTTLE_REFRESH=1
LIBC_FORCE_NOCHECK=1
HISTCONTROL=ignoreboth:eraseboth
HISTSIZE=5
LESSHISTFILE=-
LESSHISTSIZE=0
LESSSECURE=1
PAGER=less" >>/etc/environment

mkdir -p /etc/modprobe.d
echo -e "blacklist pcspkr
blacklist snd_pcsp
blacklist lpc_ich
blacklist gpio-ich
blacklist iTCO_wdt
blacklist iTCO_vendor_support
blacklist joydev
blacklist mousedev
blacklist mac_hid
blacklist uvcvideo
blacklist parport_pc
blacklist parport
blacklist lp
blacklist ppdev
blacklist sunrpc
blacklist floppy
blacklist arkfb
blacklist aty128fb
blacklist atyfb
blacklist radeonfb
blacklist cirrusfb
blacklist cyber2000fb
blacklist kyrofb
blacklist matroxfb_base
blacklist mb862xxfb
blacklist neofb
blacklist pm2fb
blacklist pm3fb
blacklist s3fb
blacklist savagefb
blacklist sisfb
blacklist tdfxfb
blacklist tridentfb
blacklist vt8623fb
blacklist sp5100-tco
blacklist sp5100_tco
blacklist pcmcia
blacklist yenta_socket
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
blacklist n-hdlc
blacklist ax25
blacklist netrom
blacklist x25
blacklist rose
blacklist decnet
blacklist econet
blacklist af_802154
blacklist ipx
blacklist appletalk
blacklist psnap
blacklist p8022
blacklist p8023
blacklist llc
blacklist i2400m
blacklist i2400m_usb
blacklist wimax
blacklist parport
blacklist parport_pc
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist wl
blacklist ssb
blacklist b43
blacklist b43legacy
blacklist bcma
blacklist bcm43xx
blacklist brcm80211
blacklist brcmfmac
blacklist brcmsmac" >/etc/modprobe.d/nomisc.conf

echo "options vfio_pci disable_vga=1
options cec debug=0
options kvm mmu_audit=0
options kvm ignore_msrs=1
options kvm report_ignored_msrs=0
options kvm kvmclock_periodic_sync=1
options nfs enable_ino64=1
options pstore backend=null
options libata allow_tpm=0
options libata ignore_hpa=0
options libahci ignore_sss=1
options libahci skip_host_reset=1
options snd_hda_intel power_save=1
options snd_ac97_codec power_save=1
options uhci-hcd debug=0
options usbhid mousepoll=20 kbpoll=20 jspoll=20
options usb-storage quirks=p
options usbcore usbfs_snoop=0
options usbcore autosuspend=10" >/etc/modprobe.d/misc.conf

echo -e "options processor ignore_ppc=1" >/etc/modprobe.d/ignore_ppc.conf

echo -e "options drm_kms_helper poll=0" >/etc/modprobe.d/disable-gpu-polling.conf

echo -e "options nvidia NVreg_UsePageAttributeTable=1 NVreg_InitializeSystemMemoryAllocations=0 NVreg_DynamicPowerManagement=0x02" >/etc/modprobe.d/nvidia.conf

echo -e "options amdgpu si_support=1 cik_support=1
options radeon si_support=0 cik_support=0" >/etc/modprobe.d/amd.conf

echo -e "options i915 fastboot=1 enable_guc=2 enable_dc=4 enable_hangcheck=0 error_capture=0" >/etc/modprobe.d/intel.conf

mkdir -p /etc/modules-load.d
echo -e "ntsync" >/etc/modules-load.d/ntsync.conf
echo -e "bfq" >/etc/modules-load.d/bfq.conf
echo -e "tcp_bbr" >/etc/modules-load.d/bbr.conf

mkdir -p /lib/sysctl.d
echo -e "net.ipv4.tcp_congestion_control=bbr" >/lib/sysctl.d/99-tcp.conf
echo -e "kernel.core_pattern=/dev/null" >/lib/sysctl.d/50-coredump.conf

echo -e "vm.swappiness = 1
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 0
vm.overcommit_ratio = 50
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
vm.stat_interval = 60
vm.page-cluster = 0
vm.dirty_expire_centisecs = 500
vm.dirty_writeback_centisecs = 1500
vm.oom_dump_tasks = 0
vm.oom_kill_allocating_task = 1
vm.extfrag_threshold = 500
vm.block_dump = 0
vm.reap_mem_on_sigkill = 1
vm.panic_on_oom = 0
vm.zone_reclaim_mode = 0
vm.scan_unevictable_pages = 0
vm.compact_unevictable_allowed = 1
vm.compaction_proactiveness = 0
vm.page_lock_unfairness = 1
vm.percpu_pagelist_high_fraction = 0
vm.pagecache = 1
vm.watermark_scale_factor = 1
vm.memory_failure_recovery = 0
vm.max_map_count = 262144
min_perf_pct = 100
kernel.sysrq = 0
kernel.nmi_watchdog = 0
kernel.printk = 3 3 3 3
kernel.printk_devkmsg = off
kernel.perf_event_paranoid = -1
kernel.kptr_restrict = 2
debug.exception-trace = 0
debug.kprobes-optimization = 1
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 1048576
fs.inotify.max_queued_events = 1048576
fs.quota.allocated_dquots = 0
fs.quota.cache_hits = 0
fs.quota.drops = 0
fs.quota.free_dquots = 0
fs.quota.lookups = 0
fs.quota.reads = 0
fs.quota.syncs = 0
fs.quota.warnings = 0
fs.quota.writes = 0
fs.leases-enable = 1
fs.lease-break-time = 5
fs.dir-notify-enable = 0
force_latency = 1
net.core.bpf_jit_enable=1
net.core.bpf_jit_harden=0
net.core.bpf_jit_kallsyms=0
vm.min_free_kbytes=2048
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
fs.file-max=1048576
fs.nr_open=1048576
fs.aio-max-nr=524288
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
fs.suid_dumpable=0
abi.vsyscall32=0
kernel.split_lock_mitigate=0
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=1
kernel.dmesg_restrict=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.arp_evict_nocarrier=1
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.all.log_martians=0
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.udp_early_demux=1
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.route.flush=1
net.ipv4.ipfrag_time=0
net.ipv4.ipfrag_secret_interval=0
net.core.default_qdisc=cake
net.core.busy_poll=50
net.core.busy_read=50
net.core.high_order_alloc_disable=0
net.core.warnings=0
net.core.tstamp_allow_data=1
net.core.enable_tcp_offloading=1
net.core.netdev_tstamp_prequeue=1
net.core.netdev_max_backlog=65535
net.core.somaxconn=65535
net.core.optmem_max=65535
net.core.rmem_max=6291456
net.core.wmem_max=6291456" >/lib/sysctl.d/99-swappiness.conf
sysctl -w vm.compact_memory=1 && sysctl -w vm.drop_caches=3

mkdir -p /etc/udev/rules.d
echo -e 'ACTION=="add|change", ATTR{queue/scheduler}=="*bfq*", KERNEL=="sd*[!0-9]|sr*|mmcblk[0-9]*|nvme[0-9]*", ATTR{queue/scheduler}="bfq"' >/etc/udev/rules.d/60-scheduler.rules
echo -e 'ACTION=="add|change", KERNEL=="sd*[!0-9]|sr*|mmcblk[0-9]*|nvme[0-9]*", ATTR{queue/iosched/slice_idle}="0", ATTR{queue/iosched/low_latency}="1"' >/etc/udev/rules.d/90-low-latency.rules
echo -e 'ACTION=="add|change", KERNEL=="sd*[!0-9]|sr*|mmcblk[0-9]*|nvme[0-9]*", ATTR{queue/add_random}="0"' >/etc/udev/rules.d/10-add-random.rules
echo -e 'ACTION=="add|change", KERNEL=="sd*[!0-9]|sr*|mmcblk[0-9]*|nvme[0-9]*", ATTR{queue/iostats}="0"' >/etc/udev/rules.d/20-iostats.rules
echo -e 'ACTION=="add|change", KERNEL=="sd*[!0-9]|sr*|mmcblk[0-9]*|nvme[0-9]*", ATTR{bdi/read_ahead_kb}="64", ATTR{queue/read_ahead_kb}="64", ATTR{queue/nr_requests}="32"' >/etc/udev/rules.d/70-readahead.rules
echo -e 'ACTION=="add|change", SUBSYSTEM=="drm", KERNEL=="card*", ATTR{device/power_dpm_state}="battery"' >/etc/udev/rules.d/30-dpm.rules
echo -e 'ACTION=="add|change", SUBSYSTEM=="scsi_host", KERNEL=="host*", ATTR{link_power_management_policy}="min_power"' >/etc/udev/rules.d/50-sata.rules

sed -i -e 's/^#udev_log=info/udev_log=err/' /etc/udev/udev.conf
sed -i -e 's/^#exec_delay=/exec_delay=0/' /etc/udev/udev.conf
sed -i -e 's/^#resolve_names=early/resolve_names=never/' /etc/udev/udev.conf

if $(find /sys/block/nvme[0-9]* | grep -q nvme); then
  echo -e "options nvme_core default_ps_max_latency_us=0" >/etc/modprobe.d/nvme.conf
fi

echo -e "options nf_conntrack nf_conntrack_helper=0" >/etc/modprobe.d/no-conntrack-helper.conf

echo -e "options iwlwifi power_save=1
options iwlmvm power_scheme=3" >/etc/modprobe.d/wlan.conf

echo -e "options rfkill default_state=0 master_switch_mode=0" >/etc/modprobe.d/wlanextra.conf

sed -i -e 's|ext4.*|ext4 rw,noatime,nodiratime,lazytime,commit=3600,delalloc,nobarrier,nofail,discard,async 0 0|g' /etc/fstab
sed -i -e 's|relatime|noatime,nodiratime,lazytime|g' /etc/fstab

echo -e "* soft nofile 524288
* hard nofile 524288
root soft nofile 524288
root hard nofile 524288
* soft memlock unlimited
* hard memlock unlimited
root soft memlock unlimited
root hard memlock unlimited" >/etc/security/limits.conf

echo -e "order bind,hosts
multi on" >/etc/host.conf

echo -e "session required pam_limits.so" >>/etc/pam.d/common-session
echo -e "session required pam_limits.so" >>/etc/pam.d/common-session-noninteractive
echo -e "session required pam_limits.so" >>/etc/pam.d/runuser-l

sed -i -e 's|022|077|g' /etc/login.defs

sed -i -e "s|\${GETTY_ARGS}|--autologin $USERNAME|g" /etc/runit/sv/agetty-tty1/run

cat /dev/null >/etc/securetty

sed -i -e 's/hosts: .*/hosts: files mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns mdns4 mdns/' /etc/nsswitch.conf

echo -e "noarp" >>/etc/dhcpcd.conf

echo -e "/home/$USERNAME/.local/bin/mksh" >>/etc/shells

rm -rfd /etc/bash/bashrc.d/*

tee /etc/issue <<"EOF"
   _  _   _     ____  _   _ _____ ____    _    _   _  ____
 _| || |_| |   / ___|| | | | ____| __ )  / \\  | \\ | |/ ___|
|_      _| |   \\___ \\| |_| |  _| |  _ \\ / _ \\ |  \\| | |  _
|_      _|_|    ___) |  _  | |___| |_) / ___ \\| |\\  | |_| |
  |_||_| (_)   |____/|_| |_|_____|____/_/   \\_\\_| \\_|\\____|

Shebang \s \r (\m) (\l) \d \t

EOF

echo -e 'NAME="Shebang Linux"
PRETTY_NAME="Shebang 25.8"
ID=shebang
ID_LIKE=artix
BUILD_ID=rolling
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://shebang-linux.github.io/"
DOCUMENTATION_URL="https://github.com/shebang-linux/shebang/"
SUPPORT_URL="https://github.com/orgs/shebang-linux/discussions/"
BUG_REPORT_URL="https://github.com/shebang-linux/shebang/issues/"
LOGO=shebang-og-logo' >/etc/os-release

for run_script in /etc/runit/sv/*/run; do
  sed -i -e '/^exec [^2&>][^1>&]/ { s|^exec |exec nice -n 19 ionice -c2 -n7 | }' "$run_script"
done

ln -s /etc/runit/sv/backlight/ /etc/runit/runsvdir/current
ln -s /etc/runit/sv/dhcpcd/ /etc/runit/runsvdir/current
ln -s /etc/runit/sv/haveged/ /etc/runit/runsvdir/current
ln -s /etc/runit/sv/tor/ /etc/runit/runsvdir/current
ln -s /etc/runit/sv/wpa_supplicant/ /etc/runit/runsvdir/current

# Configure mkinitcpio
if [ "$ENCRYPTED" = "y" ]; then
  sed -i -e 's/^HOOKS.*$/HOOKS=(base udev autodetect modconf keyboard block encrypt filesystems)/g' /etc/mkinitcpio.conf
else
  sed -i -e 's/^HOOKS.*$/HOOKS=(base udev autodetect modconf block filesystems)/g' /etc/mkinitcpio.conf
fi

sed -i -e 's/#COMPRESSION="lz4"/COMPRESSION="lz4"/g' /etc/mkinitcpio.conf
sed -i -e 's/#COMPRESSION_OPTIONS=.*/COMPRESSION_OPTIONS=("--best")/g' /etc/mkinitcpio.conf
sed -i -e 's/#MODULES_DECOMPRESS=.*/MODULES_DECOMPRESS="yes"/g' /etc/mkinitcpio.conf

tee /etc/mkinitcpio.d/linux-zen.preset <<"EOF"
ALL_kver="/boot/vmlinuz-linux-zen"
PRESETS=('default')
default_image="/boot/initramfs-linux-zen.img"
EOF

rm /boot/initramfs-linux-zen-fallback.img

mkinitcpio -P

# Install boot loader
if [ "$ENCRYPTED" = "y" ]; then
  sed -i -e "s|GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"cryptdevice=$PART2:root:allow-discards root=/dev/mapper/root quiet rootfstype=ext4 biosdevname=0 nowatchdog noautogroup noresume default_hugepagesz=2M hugepagesz=2M hugepages=256 zswap.enabled=1 zswap.compressor=lz4 zswap.max_pool_percent=10 zswap.zpool=zsmalloc workqueue.power_efficient=1 pcie_aspm=force pci=noaer rd.plymouth=0 plymouth.enable=0 plymouth.ignore-serial-consoles logo.nologo consoleblank=0 vt.global_cursor_default=0 rd.systemd.show_status=auto loglevel=0 rd.udev.log_level=0 udev.log_priority=0 enable_hangcheck=0 error_capture=0 msr.allow_writes=on audit=0 nosoftlockup selinux=0 enforcing=0 debugfs=off mce=0 mds=full,nosmt vsyscall=none no_timer_check skew_tick=1 clocksource=tsc tsc=perfect nohz=on rcutree.enable_rcu_lazy=1 rcupdate.rcu_expedited=1 rcu_nocb_poll noirqdebug iomem=relaxed iommu.passthrough=1 sched_policy=1 noreplace-smp nodiratime boot_delay=0 io_delay=none rootdelay=0 elevator=noop realloc init_on_alloc=0 init_on_free=0 pti=on no_stf_barrier mitigations=off ftrace_enabled=0 fsck.repair=no fsck.mode=skip cryptomgr.notests\"|g" /etc/default/grub
  sed -i -e '/GRUB_ENABLE_CRYPTODISK=y/s/^#//g' /etc/default/grub
else
  sed -i -e 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet rootfstype=ext4 biosdevname=0 nowatchdog noautogroup noresume default_hugepagesz=2M hugepagesz=2M hugepages=256 zswap.enabled=1 zswap.compressor=lz4 zswap.max_pool_percent=10 zswap.zpool=zsmalloc workqueue.power_efficient=1 pcie_aspm=force pci=noaer rd.plymouth=0 plymouth.enable=0 plymouth.ignore-serial-consoles logo.nologo consoleblank=0 vt.global_cursor_default=0 rd.systemd.show_status=auto loglevel=0 rd.udev.log_level=0 udev.log_priority=0 enable_hangcheck=0 error_capture=0 msr.allow_writes=on audit=0 nosoftlockup selinux=0 enforcing=0 debugfs=off mce=0 mds=full,nosmt vsyscall=none no_timer_check skew_tick=1 clocksource=tsc tsc=perfect nohz=on rcutree.enable_rcu_lazy=1 rcupdate.rcu_expedited=1 rcu_nocb_poll noirqdebug iomem=relaxed iommu.passthrough=1 sched_policy=1 noreplace-smp nodiratime boot_delay=0 io_delay=none rootdelay=0 elevator=noop realloc init_on_alloc=0 init_on_free=0 pti=on no_stf_barrier mitigations=off ftrace_enabled=0 fsck.repair=no fsck.mode=skip cryptomgr.notests"/' /etc/default/grub
fi

sed -i -e 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=0/' /etc/default/grub
sed -i -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=1/' /etc/default/grub
sed -i -e 's/GRUB_RECORDFAIL_TIMEOUT=.*/GRUB_RECORDFAIL_TIMEOUT=0/' /etc/default/grub
sed -i -e 's/GRUB_DISABLE_OS_PROBER=.*/GRUB_DISABLE_OS_PROBER=true/' /etc/default/grub
sed -i -e 's/GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY=true/' /etc/default/grub
sed -i -e 's/GRUB_DISABLE_SUBMENU=.*/GRUB_DISABLE_SUBMENU=true/' /etc/default/grub

grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=grub --recheck
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=grub --removable --recheck

# Encrypt boot loader
GRUB_PASS=$(echo -e "$ROOT_PASSWORD\n$ROOT_PASSWORD" | grub-mkpasswd-pbkdf2 | grep -oE '[^ ]+$')
echo -e "set superusers=$USERNAME
password_pbkdf2 $USERNAME $GRUB_PASS" >>/etc/grub.d/40_custom
sed -i -e 's/class os/class os --unrestricted/' /etc/grub.d/10_linux
grub-mkconfig -o /boot/grub/grub.cfg

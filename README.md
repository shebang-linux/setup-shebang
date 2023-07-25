# deploy-artix

## Overview

![](https://img.shields.io/badge/OS-Artix%20Linux-blue?logo=Artix+Linux)
<p align="center">
  <img src="https://github.com/YurinDoctrine/deploy-artix/blob/main/screenshot.png?raw=true" alt="screenshot" border="0">
</p>

This project aims to provide a smooth Artix installation experience, both for beginners and experts.
It supports both `runit` and `OpenRC` init systems. It also supports `btrfs` and `cryptsetup`.

_This installer also might appeal to you if you already are an expert but want a reproducable best-practices installation._

The installer performs the following main steps (in roughly this order),
with some parts depending on the chosen configuration:

1. Base system configuration (hostname, timezone, keymap, locales, ...)
2. Partition disks
3. Install base packages (base, base-devel, ...)
4. Install kernel
5. Install grub
6. Ensure minimal working system with my [dotfiles](https://github.com/YurinDoctrine/.config)

### Preinstallation

* ISO downloads can be found at [artixlinux.org](https://artixlinux.org/download.php)
* ISO files can be burned to drives with `dd` or something like Etcher.
* `sudo dd bs=4M if=/path/to/artix.iso of=/dev/sd[drive letter] status=progress`
* A better method these days is to use [Ventoy](https://www.ventoy.net/en/index.html).

### Usage

1. Boot into live environment (both login and password are `artix`).
2. Connect to the internet. Ethernet is setup automatically, and WiFi is done with something like:
```
sudo rfkill unblock wifi
sudo ip link set wlan0 up
connmanctl # In Connman, use respectively: `agent on`, `scan wifi`, `services`, `connect wifi_NAME`, `quit`
```
3. Run the script:
```
sudo pacman -Sy --noconfirm parted # A program for creating, destroying, resizing, checking and copying partitions

bash <(curl -s https://raw.githubusercontent.com/YurinDoctrine/deploy-artix/main/setup.sh)
```
4. When everything finishes, `reboot` or `poweroff` then remove the installation media and boot into Artix. The post-installation networking is done with Connman.

#### References

* [Artix Wiki Installation](https://wiki.artixlinux.org/Main/Installation)

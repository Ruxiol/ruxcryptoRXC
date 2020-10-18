
Debian
====================
This directory contains files used to package ruxcryptod/ruxcrypto-qt
for Debian-based Linux systems. If you compile ruxcryptod/ruxcrypto-qt yourself, there are some useful files here.

## ruxcrypto: URI support ##


ruxcrypto-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install ruxcrypto-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your ruxcrypto-qt binary to `/usr/bin`
and the `../../share/pixmaps/ruxcrypto128.png` to `/usr/share/pixmaps`

ruxcrypto-qt.protocol (KDE)


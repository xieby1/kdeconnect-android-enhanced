# KDE Connect Android Enhanced

Use KDE Connect Android Enhanced together
with [KDE Connect Enhanced](https://github.com/xieby1/kdeconnect-kde-enhanced)(Linux),
or with [Gnome Extension: GSConnect](https://github.com/GSConnect/gnome-shell-extension-gsconnect).

## Intro

Make KDE Connect remote keyboard better, especially for termux!


A toggle button is added to KDE Connect remote keyboard,
which switch between original mode and non-original mode.

* In non-original mode, which is default,
  * `Enter` key works as expected, no need to be bother by `ctrl-j` any more.
  * `Ctrl-C` works as expected. You can esaily interrupt the running programs now.
  * `Ctrl-V` clipboard works. You can paste your linux's content to your android device.
* In original, everything is the same as original KDE Connect Android App.

If you only install enhanced android app, but do not install enhanced linux app,
only `Enter` key can work, `Ctrl-C` & `Ctrl-V` rely on enhanced linux app.

## Compile/Install

Compile/Install is the same as original KDE Connect Android App.

Or you can download pre-built apk from [release](https://github.com/xieby1/kdeconnect-android-enhanced/releases).

### Nix/NixOS

If you want to build in nix/nixos,

TODO: sdk installation problem

```bash
nix-shell
gradlew build
```

## TODO

* Add a icon for toggle button.

# KDE Connect - Android app

KDE Connect is a multi-platform app that allows your devices to communicate (eg: your phone and your computer).

## (Some) Features
- **Shared clipboard**: copy and paste between your phone and your computer (or any other device).
- **Notification sync**: Read and reply to your Android notifications from the desktop.
- **Share files and URLs** instantly from one device to another.
- **Multimedia remote control**: Use your phone as a remote for Linux media players.
- **Virtual touchpad**: Use your phone screen as your computer's touchpad and keyboard.

All this without wires, over the already existing WiFi network, and using TLS encryption.

## About this app

This is a native Android port of the KDE Connect Qt app. You will find a more complete readme about KDE Connect [here](https://invent.kde.org/network/kdeconnect-kde/).

## How to install this app

You can install this app from the [Play Store](https://play.google.com/store/apps/details?id=org.kde.kdeconnect_tp) as well as [F-Droid](https://f-droid.org/repository/browse/?fdid=org.kde.kdeconnect_tp). Note you will also need to install the [desktop app](https://invent.kde.org/network/kdeconnect-kde) for it to work.

## Contributing

A lot of useful information, including how to get started working on KDE Connect and how to connect with the current developers, is on our [KDE Community Wiki page](https://community.kde.org/KDEConnect)

For bug reporting, please use [KDE's Bugzilla](https://bugs.kde.org). Please do not use the issue tracker in GitLab since we want to keep everything in one place.

To contribute patches, use [KDE Connect's Gitlab](https://invent.kde.org/kde/kdeconnect-android/).
On Gitlab (as well as on our [old Phabricator](https://phabricator.kde.org/tag/kde_connect/)) you can find a task list with stuff to do and links to other relevant resources.
It is a good idea to also subscribe to the [KDE Connect mailing list](https://mail.kde.org/mailman/listinfo/kdeconnect).

Please know that all translations for all KDE apps are handled by the [localization team](https://l10n.kde.org/). If you would like to submit a translation, that should be done by working with the proper team for that language.

## License
[GNU GPL v2](https://www.gnu.org/licenses/gpl-2.0.html) and [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.html)

If you are reading this from Github, you should know that this is just a mirror of the [KDE Project repo](https://invent.kde.org/network/kdeconnect-android/).

---
layout: post
title: Windows PrivEsc cheatsheet
tags: [OSCP, Cheatsheet, Windows]
description: "Windows PrivEsc cheatsheet"
---

# Table of contents

- [Introduction](#introduction)
- [Tools](#tools)
- [Kernel](#kernel)
- [Services](#services)
  - [BinPath](#binpath)
  - [Unquoted Service Path](#unquoted-service-path)
  - [Registry](#registry)
  - [Executable file](#executable-file)
  - [DLL Hijacking](dll-hijacking)
- [Password mining](#password-mining)
  - [Passwords stored by user](#passwords-stored-by-user)
  - [Registry](#registry)
  - [Configuration Files](#configuration-files)
- [Registry](#registry)
  - [AutoRun](#autorun)
  - [AllwaysInstallElevated](#allwaysinstallelevated)
- [Scheduled Tasks](#scheduled-tasks)
- [Hot Potato](#hot-potato)
  - [Detect](#detect)
  - [Exploit](#exploit)
- [Startup Aplications](#startup-aplications)
- [Firewalled Services](#firewalled-services)

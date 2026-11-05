---
title: How I stopped leaking secrets on screen shares: nvim-secrets
tags: 
  - terminal
---

I often stream or screen share for things all the time and the one thing that has slowed production of content has been
the trying to work around secrets. In my terminal I'm always trying to figure out how to share what is needed without
leaking an API key or a password.

I decided to use tools that I already have and those combined with AI I think I have solved much of the problem with [nvim-secrets].

nvim-secrets runs a masking parser on detected secrets. The buffer text is never modified but in _masked_ in NORMAL and VISUAL mode. In INSERT/REPLACE mode, the secret on the cursor line is shown (it can be configured to the whole buffer).

**What this is not a complete leak prevention**, but it only works by using tools that are can help prevent leaks.

There is a custom lua secrets detection parser but it's only for those extreme edgecases that have been found in usage. Instead, I wanted to use tools designed for this. By default this uses [betterleaks] and can also use [gitleaks], or [ripsecrets].

This means that you can use whichever local tool you prefer and all changes are local.

## bat-secrets and rg-secrets — the same masking in the terminal

nvim-secrets, only covers 1/2 of the troubles that I wind up dealing with. Most accidental leaks come from looking for other pieces of information. This happens with tools like [ripgrep] and [bat]. I reused the same `detect.lua` patterns and scanners as the plugin: a pattern added once works in both.

These work by calling the commands and then passing them through the same scanners. The main command's options pass-through. This means you're getting the best of both.

## 7. Honest limitations

This isn't perfect. Nowhere near. I have found a couple quirks in how it detects. But it has significantly reduced the amount of times I've accidentally leaked something in a meeting while screen sharing.

## 8. Closing

I encourage you to give these a shot. You can install nvim secrets like most nvim plugins and

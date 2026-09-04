# Protarium fork of Inkay — Black Ops II Wii U support

Fork of [PretendoNetwork/Inkay](https://github.com/PretendoNetwork/Inkay),
**GPL-3.0** (see `LICENSE`). Everything upstream keeps working; this fork adds
game-specific patches for **Call of Duty: Black Ops II on Wii U**, whose online
runs on Activision Demonware rather than Nintendo NEX.

## What this fork adds

**`src/patches/bo2_auth.cpp` / `.h`** — new. In-memory patches to
`t6mp_cafef_rpl.rpl` (USA and EUR, verified byte-identical at every patch site):

- Neutralise the RSA-signature branch on `WiiUForMmpReply2` and the follow-up
  ticket "magic" check. The ticket is still 3DES-decrypted with the PID-derived
  key, so this is not a blanket auth bypass — it only skips a signature we
  cannot reproduce without Nintendo's private key.
- Relax `Live_GetConnectivityInformation`'s required bitmask to the two sign-in
  bits, so the "connecting to online services" popup does not hang on service
  replies a self-hosted backend does not fully provide.
- Force `LiveStorage_DoWeHaveAllStats` and `Live_HasMultiplayerPrivileges` to
  return true (new-player state; stats fill in from play).
- Force the session-advertising branch in `Session_StartHost_Platform_DW`
  (`FORCE_ADVERTISE_BRANCH`) so lobbies reach the matchmaking server. An
  alternative m_active-gate approach is kept behind the same flag.
- Optional: rebind bdNet's UDP port from 3074 to a forwardable one
  (`BO2_REBIND_BDNET_PORT`, off by default) for shared-IPv4 / CGNAT lines.
- A diagnostic probe reading live bdNet/matchmaking state is present but
  **compiled out** (`BO2_ENABLE_DIAG_PROBE`, default 0).

Every address is applied only after the opcode at the site matches what the
known build holds; an unrecognised build is left untouched.

**`src/patches/dns_hooks.cpp`** — extended. Redirects the `*.demonware.net`
hosts BO2 resolves (`ops2-wiiu-{cs,auth,tu-auth,lobby,lsg,ls,stun,storage,codtv,
umbrella}`, `cod7-stun.{eu,us,jp,au}`) to the self-hosted endpoints, and uses
the first Demonware resolution as the trigger to apply `patch_bo2_auth()`.

**`src/main.cpp`** — three lines: include, `reset_bo2_auth_patch()` per launch,
`patch_bo2_auth()` call.

**`common/inkay_config.h`** — `BO2_OPS2_{CS,AUTH,LOBBY}_HOST` defaults, derived
from `NETWORK_BASEURL` like every other Inkay endpoint. Point them at your own
server via `inkay_config.local.h` (git-ignored).

## The server side

The Demonware backend these patches talk to is a separate project
(`open-bitdemon-emulator` fork). This repo is only the console-side plumbing.

## Building

Unchanged from upstream:

```
docker build -t inkay .
docker run --rm -v "$(pwd):/app" inkay make
```

Output: `dist/Inkay-pretendo.wms` (WUMS module) + `dist/Inkay-pretendo.wps`
(WUPS plugin).

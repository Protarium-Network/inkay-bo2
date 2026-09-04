/*  Copyright 2024 Pretendo Network contributors <pretendo.network>
    Copyright 2024 Ash Logan <ash@heyquark.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <netdb.h>

#include "config.h"
#include "utils/logger.h"
#include "inkay_config.h"
#include "bo2_auth.h"
#include <array>
#include <vector>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <function_patcher/function_patching.h>

// Temporary ground-truth diagnostic: file-based logging on SD, independent of
// WHBLogUdp (which is unverifiable when the listening PC can't be reached
// over broadcast). Remove once the wahp redirect is confirmed working.
static void dns_debug_log(const char *fmt, ...) {
    FILE *f = fopen("/vol/external01/wiiu/dns_debug.log", "a");
    if (!f) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

std::vector<PatchedFunctionHandle> dns_patches;

constexpr std::pair<const char *, const char *> dns_replacements[] = {
        // NNCS servers
        { "nncs1.app.nintendowifi.net", "nncs1.app." NETWORK_BASEURL },
        { "nncs2.app.nintendowifi.net", "nncs2.app." NETWORK_BASEURL },

        // Karaoke U / JOYSOUND Orchestra control service. Nintendo's
        // retired backend now returns HTTP 503, so route it to the local
        // compatibility endpoint hosted behind the account proxy.
        { "ssl.wahp.wah.wup.app.nintendo.net", KARAOKE_CONTROL_HOST },

        // Super Mario Maker's 100 Mario Challenge playlist service. This is
        // an ordinary game-process HTTPS lookup, so the DNS hook can route it
        // to our local pickup API while leaving every other SMM/NEX request
        // untouched.
        { "wup-ama.app.nintendo.net", SMM_PICKUP_HOST },

        // Monster Hunter 3 Ultimate's Capcom Browser Services endpoint.
        { "goshawk.capcom.co.jp", MH3U_GOSHAWK_HOST },

        // Demae-Can Wii U channel. The real nws.demae-can.com backend shut
        // down 2017-03-31 and the domain doesn't even resolve in public DNS
        // anymore - it's a third-party company's server, not Nintendo's, so
        // it has nothing to do with NETWORK_BASEURL. Route to a self-hosted
        // replacement instead.
        { "nws.demae-can.com", DEMAECAN_HOST },

        // BOSS (Background Online Storage Service) - SpotPass, tasksheets,
        // StreetPass relay, standby-mode notification delivery.
        { "npdi.cdn.nintendo.net", BOSS_NPDI_HOST },
        { "npdl.cdn.nintendo.net", BOSS_NPDL_HOST },
        { "npfl.c.app.nintendo.net", BOSS_NPFL_HOST },
        { "nppl.app.nintendo.net", BOSS_NPPL_HOST },
        { "nppl.c.app.nintendo.net", BOSS_NPPL_HOST },
        { "npts.app.nintendo.net", BOSS_NPTS_HOST },
        { "service.spr.app.nintendo.net", BOSS_SPR_HOST },

        // Call of Duty: Black Ops II (Wii U) - Demonware "ops2" backend.
        // Base game resolves "-auth"; a title-updated console resolves
        // "-tu-auth". cs/storage/codtv ride the CS host; lobby/lsg/ls/stun/
        // umbrella + cod7-stun.* ride the lobby host. Both ".prod.demonware.net"
        // and bare ".demonware.net" are covered; a wildcard fallback in
        // replace_dns_name() catches anything else *.demonware.net.
        { "ops2-wiiu-cs.prod.demonware.net",       BO2_OPS2_CS_HOST },
        { "ops2-wiiu-cs.demonware.net",            BO2_OPS2_CS_HOST },
        { "ops2-wiiu-storage.prod.demonware.net",  BO2_OPS2_CS_HOST },
        { "ops2-wiiu-storage.demonware.net",       BO2_OPS2_CS_HOST },
        { "ops2-wiiu-codtv.prod.demonware.net",    BO2_OPS2_CS_HOST },
        { "ops2-wiiu-codtv.demonware.net",         BO2_OPS2_CS_HOST },
        { "ops2-wiiu-auth.prod.demonware.net",     BO2_OPS2_AUTH_HOST },
        { "ops2-wiiu-auth.demonware.net",          BO2_OPS2_AUTH_HOST },
        { "ops2-wiiu-tu-auth.prod.demonware.net",  BO2_OPS2_AUTH_HOST },
        { "ops2-wiiu-tu-auth.demonware.net",       BO2_OPS2_AUTH_HOST },
        { "ops2-wiiu-lobby.prod.demonware.net",    BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-lobby.demonware.net",         BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-lsg.prod.demonware.net",      BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-lsg.demonware.net",           BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-ls.prod.demonware.net",       BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-ls.demonware.net",            BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-stun.prod.demonware.net",     BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-stun.demonware.net",          BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-umbrella.prod.demonware.net", BO2_OPS2_LOBBY_HOST },
        { "ops2-wiiu-umbrella.demonware.net",      BO2_OPS2_LOBBY_HOST },
        { "cod7-stun.eu.demonware.net",            BO2_OPS2_LOBBY_HOST },
        { "cod7-stun.us.demonware.net",            BO2_OPS2_LOBBY_HOST },
        { "cod7-stun.jp.demonware.net",            BO2_OPS2_LOBBY_HOST },
        { "cod7-stun.au.demonware.net",            BO2_OPS2_LOBBY_HOST },
};

static const char * replace_dns_name(const char *dns_name) {
    if (!Config::connect_to_network) {
        dns_debug_log("replace_dns_name(\"%s\") -> connect_to_network is FALSE, passthrough", dns_name ? dns_name : "(null)");
        return dns_name;
    }

    const bool is_demonware = dns_name && strstr(dns_name, "demonware.net") != nullptr;
    if (is_demonware) {
        // By the time BO2 resolves a Demonware host, its multiplayer RPL
        // (t6mp_cafef_rpl.rpl) is already loaded, so this is a safe place to
        // apply the auth-compatibility patch without hooking the RPL loader.
        patch_bo2_auth();
    }

    for (auto [original, replacement] : dns_replacements) {
        if (strcmp(original, dns_name) == 0) {
            dns_debug_log("replace_dns_name(\"%s\") -> MATCHED, replaced with \"%s\"", dns_name, replacement);
            return replacement;
        }
    }

    // Wildcard fallback for any other *.demonware.net host BO2 might resolve.
    if (is_demonware) {
        const char *repl;
        if (strstr(dns_name, "auth") != nullptr) {
            repl = BO2_OPS2_AUTH_HOST;
        } else if (strstr(dns_name, "-cs") != nullptr || strstr(dns_name, "content") != nullptr ||
                   strstr(dns_name, "storage") != nullptr || strstr(dns_name, "codtv") != nullptr) {
            repl = BO2_OPS2_CS_HOST;
        } else {
            repl = BO2_OPS2_LOBBY_HOST;
        }
        dns_debug_log("replace_dns_name(\"%s\") -> demonware wildcard, replaced with \"%s\"", dns_name, repl);
        return repl;
    }

    dns_debug_log("replace_dns_name(\"%s\") -> no match, passthrough", dns_name ? dns_name : "(null)");
    return dns_name;
}

DECL_FUNCTION(struct hostent *, gethostbyname, const char *dns_name) {
    dns_debug_log("my_gethostbyname called with \"%s\"", dns_name ? dns_name : "(null)");
    return real_gethostbyname(replace_dns_name(dns_name));
}

DECL_FUNCTION(int, getaddrinfo, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    dns_debug_log("my_getaddrinfo called with node=\"%s\" service=\"%s\"", node ? node : "(null)", service ? service : "(null)");
    return real_getaddrinfo(replace_dns_name(node), service, hints, res);
}

void patchDNS() {
    dns_debug_log("=== patchDNS() called, connect_to_network=%d ===", (int) Config::connect_to_network);
    dns_patches.reserve(2);

    auto add_patch = [](function_replacement_data_t repl, const char *name) {
        PatchedFunctionHandle handle = 0;
        bool has_been_patched = false;
        FunctionPatcherStatus status = FunctionPatcher_AddFunctionPatch(&repl, &handle, &has_been_patched);
        dns_debug_log("patchDNS: %s -> status=%d has_been_patched=%d handle=%u", name, (int) status, (int) has_been_patched, (unsigned) handle);
        if (status != FUNCTION_PATCHER_RESULT_SUCCESS) {
            DEBUG_FUNCTION_LINE("Inkay/DNS: Failed to patch %s!", name);
        }
        dns_patches.push_back(handle);
    };

    // Plain REPLACE_FUNCTION only patches whichever process is running when
    // Inkay_Initialize() runs (the Wii U Menu, since the plugin's
    // INITIALIZE_PLUGIN() fires once at boot and is never re-run per game -
    // see plugin/src/main.cpp). It never reaches a game's own process, so
    // any dns_replacements entry that a *game* itself needs to hit (e.g.
    // Karaoke U's wahp lookup) silently never applies. FP_TARGET_PROCESS_GAME
    // patches the launched game's process instead, matching the pattern
    // already used for FSOpenFile/FSReadFile/FSCloseFile in
    // account_settings.cpp/eshop_applet.cpp/olv_applet.cpp.
    add_patch(REPLACE_FUNCTION_FOR_PROCESS(gethostbyname, LIBRARY_NSYSNET, gethostbyname, FP_TARGET_PROCESS_GAME), "gethostbyname");

    add_patch(REPLACE_FUNCTION_FOR_PROCESS(getaddrinfo, LIBRARY_NSYSNET, getaddrinfo, FP_TARGET_PROCESS_GAME), "getaddrinfo");
}

void unpatchDNS() {
    for (auto handle: dns_patches) {
        FunctionPatcher_RemoveFunctionPatch(handle);
    }
    dns_patches.clear();
}

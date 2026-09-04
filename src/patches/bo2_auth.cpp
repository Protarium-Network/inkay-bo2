#include "bo2_auth.h"

#include <cstdio>
#include <cstring>
#include <coreinit/cache.h>
#include <coreinit/thread.h>
#include <coreinit/time.h>
#include <coreinit/title.h>
#include <string_view>

#include "config.h"
#include "Notification.h"
#include "sysconfig.h"
#include "utils/logger.h"
#include "utils/replace_mem.h"
#include "utils/rpl_info.h"

using namespace std::string_view_literals;

namespace {
constexpr uint64_t BO2_USA_TITLE_ID = 0x00050000'1010cf00;
constexpr uint64_t BO2_EUR_TITLE_ID = 0x00050000'10113400;

// t6mp_cafef_rpl.rpl, both regions supported. Every address in this file is
// applied by absolute value, so it must match on the RPL actually loaded.
//
//   USA  SHA-256 3B30AB9F0D487C9508DA81E1547A64FD95DC6E58A97724ECF57EBBEEE04FF63F
//   EUR  SHA-256 C21BD87F0CC58D7FC8C0CB846015E935B9F88B9CE3B8D33C2F10A6A85CC632AE
//
// The two builds are byte-identical in .rodata and .data and differ in only 6
// bytes across all of .text (retail region code near 0x02194000, 0x02434000,
// 0x0246b000, 0x02514000, 0x02537000, 0x02977000) - none at a patch site. So a
// single address set covers both; verified by a full section diff of the
// decompressed modules. If a future title update diverges, split the constants
// into a table keyed on OSGetTitleID() rather than widening this comment.
//
// The console rejects our WiiUForMmpReply2 because it verifies an RSA
// signature we cannot reproduce (no Nintendo private key). Neutralise the
// branch that acts on the RSA check, and NOP the follow-up ticket "magic"
// check. The ticket itself is still 3DES-decrypted with the key derived from
// the PID, so this is not a blanket auth bypass.
constexpr uint32_t RSA_VERIFY_BRANCH = 0x02a2e69c;
constexpr uint32_t ORIGINAL_BNE = 0x40820070;  // bne 0x02a2e70c
constexpr uint32_t BYPASS_BRANCH = 0x48000070;  // b   0x02a2e70c

constexpr uint32_t TICKET_MAGIC_BRANCH = 0x02a2e754;
constexpr uint32_t ORIGINAL_MAGIC_BNE = 0x40820068;  // bne 0x02a2e7bc
constexpr uint32_t BYPASS_MAGIC_CHECK = 0x60000000;  // nop

// Live_GetConnectivityInformation__F17ControllerIndex_tRib @ 0x0268df84 builds a
// bitmask of "online sub-system ready" flags and returns 1 only when every bit in
// a required mask is set: 0x1BEE for multiplayer, 0x11EE for zombies. That return
// value is what __IsDemonwareFetchingDone (the LUI menu-script expression) waits on
// before leaving the "connecting to online services" popup for the MP menu.
//
// Against a self-hosted BitDemon emulator we reliably satisfy only the sign-in
// bits (0x2 Live, 0x4 Demonware). The rest - DoWeHaveAllStats (0x8), net-link
// state (0x20), FFOTD/WAD/playlists (0x40/0x80/0x100), IsTimeSynced (0x200),
// DoWeHaveLeagues (0x800), geo-location (0x1000) - depend on service replies the
// emulator does not fully provide, so the popup hangs until the lobby socket
// idle-times-out (~5 min) and shows PLATFORM_DEMONWARE_DISCONNECT.
//
// Relax the required mask to 0x6 (both sign-in bits only). Every other subsystem
// is still fetched/retried every frame by Live_FrameForController; it just no
// longer gates the menu transition.
constexpr uint32_t PPC_NOP = 0x60000000;

struct BranchPatch {
    uint32_t address;
    uint32_t original;
};

// Every flag in Live_GetConnectivityInformation is set by the pattern
//     bl <check> ; cmpwi r3,0 ; b(eq|ne) <skip> ; lwz rN,0(r30) ; ori rN,rN,<bit> ; stw
// NOP-ing the branch makes the `ori` unconditional, so the bit is always set.
// Addresses/opcodes verified against t6mp_cafef_rpl update v128.
constexpr BranchPatch CONNECTIVITY_BRANCHES[] = {
    {0x0268dff4, 0x41820010},  // 0x0002 signed in to Live
    {0x0268e03c, 0x41820010},  // 0x0004 signed in to Demonware
    {0x0268e058, 0x40820010},  // 0x0020 network link state == 6 (bne)
    {0x0268e070, 0x41820010},  // 0x0040 LiveStorage_DoWeHaveFFOTD
    {0x0268e088, 0x41820010},  // 0x0100 LiveStorage_ValidateFFOTD
    {0x0268e0a4, 0x41820010},  // 0x0008 LiveStorage_DoWeHaveAllStats
    {0x0268e0bc, 0x41820010},  // 0x0080 LiveStorage_DoWeHavePlaylists
    {0x0268e0f0, 0x41820010},  // 0x0800 LiveStorage_DoWeHaveLeagues
    {0x0268e108, 0x41820010},  // 0x0200 LiveStorage_IsTimeSynced
    {0x0268e13c, 0x41820010},  // 0x1000 geo-location data retrieved
};

// Session_StartHost_Platform_DW @0x026b8fc0 is where a lobby either gets
// announced to matchmaking or stays invisible:
//     026b8ffc  57ea0739  rlwinm. r10,r31,0,28,28   ; r10 = flags & 8  (r31 = flags)
//     026b9000  4182007c  beq     0x026b907c        ; bit clear -> only StartTask
// Taking that branch skips the block that sets m_SHOW_IN_MATCHMAKING and calls
// dwCreateSession, so the console hosts privately and the server never hears
// about it. Measured on-console: 35 FindSessions over 30 minutes with the retry
// interval plateauing near 100 s, and not a single CreateSession - the branch is
// always taken. NOP-ing it forces the announcement.
//
// This is deliberately broad: it also advertises sessions the game would have
// kept private (custom games). That is the point for now - it proves whether the
// rest of the create/find path works at all. Narrow it once a CreateSession has
// actually been observed on the wire.
constexpr uint32_t ADVERTISE_BRANCH = 0x026b9000;
constexpr uint32_t ADVERTISE_BRANCH_ORIGINAL = 0x4182007c;

// Two mutually exclusive advertising strategies. Pick exactly one.
//
//  true  (r36/r37): NOP the branch here so the session is always announced. It
//        also announces the party the instant a playlist is entered, so a
//        console becomes a host before it has searched - the server then breaks
//        the tie (BO2_MM_ASYMMETRIC) so exactly one side of any pair joins the
//        other. This is the path that has produced real CreateSessions and
//        reached "Joining game lobby".
//
//  false (r42-r44): leave this branch alone and NOP the two m_active gates
//        instead (DOUPDATE_GATE + SESSION_MODIFY_GATE), letting the game's own
//        PartyHost_Frame -> Session_ChangeAdvertisedStatus -> Session_Modify
//        route drive the announcement. Cleaner in theory; measured zero
//        CreateSessions in practice.
constexpr bool FORCE_ADVERTISE_BRANCH = true;

// Session_Modify (RPL 0x026b8580) is the real advertising path, and it gives up
// on one field:
//     026b85b4  lwzu r11,0x4038(r30)   ; g_matchmakingInfo
//     026b85b8  lwz  r0,0x174(r11)
//     026b85bc  cmpwi r0,0x0
//     026b85c0  4182007c  beq 0x026b863c   ; zero -> skip the whole body
//
// Read off a hosting console: adv=1, dirty=1, and this field 0. The game has
// asked to be advertised and is blocked here. Every store to +0x174 found
// anywhere in the module writes zero (teardown paths and the constructor), and
// nothing was found that sets it - so either it is genuinely never activated in
// this configuration, or the field is not what the dedicated server's symbols
// call m_active. Either way the measurement stands, so drop the gate and let the
// path run.
constexpr uint32_t SESSION_MODIFY_GATE = 0x026b85c0;
constexpr uint32_t SESSION_MODIFY_GATE_ORIGINAL = 0x4182007c;

// The same field is tested twice, and this is the test that runs first.
//
// MatchMakingInfo::doUpdate (RPL 0x022585b0) is called every frame from
// Live_Frame and decides whether the pending change is worth pushing:
//     022585b0  lwz   r10,0x174(r3)   ; m_active
//     022585b4  cmpwi r10,0x0
//     022585bc  4182004c  beq 0x02258608   ; zero -> return false
// Returning false there means Session_Modify is never called at all, so patching
// only the gate inside Session_Modify (above) patches dead code - measured: with
// that alone, still zero CreateSession.
//
// With both dropped, m_dirty becomes the trigger, which is what
// Session_ChangeAdvertisedStatus raises and what the on-console probe reads as 1.
constexpr uint32_t DOUPDATE_GATE = 0x022585bc;
constexpr uint32_t DOUPDATE_GATE_ORIGINAL = 0x4182004c;

// Move the local UDP port bdNet binds.
//
// bdNetStartParams::bdNetStartParams (RPL 0x02a0aca8) hardcodes it:
//     02a0acdc  3bc00c02  li  r30,0xc02      ; 3074
//     02a0acec  b3df0002  sth r30,0x2(r31)   ; params + 0x2 = the port
// dwNetStart just default-constructs the params, so this is the value that ends
// up on the socket. The Demonware server address is a separate bdAddr resolved
// by DNS, so changing this does not affect reaching the backend.
//
// Why bother: on a shared-IPv4 line (Free/Freebox and most CGNAT setups) the
// subscriber only owns a slice of the public port space - the router refuses to
// forward anything below 16384 - so UDP 3074 can never be opened. Rebinding the
// game into that slice makes a port forward possible, which is what the QoS
// probe needs before a lobby is considered joinable.
//
// 30000 stays under 0x8000 so `li` still encodes it as a positive immediate;
// anything above 32767 would need a different instruction.
constexpr uint32_t BDNET_PORT_INSN = 0x02a0acdc;
constexpr uint32_t BDNET_PORT_ORIGINAL = 0x3bc00c02;  // li r30, 3074
constexpr uint16_t BDNET_PORT_NEW = 30000;
constexpr uint32_t BDNET_PORT_PATCHED = 0x3bc00000u | BDNET_PORT_NEW;

// Only rebind the port on a line that cannot forward UDP 3074. Everyone else
// stays on 3074, which is what the bdNet responder and NAT logic default to.
#ifndef BO2_REBIND_BDNET_PORT
#define BO2_REBIND_BDNET_PORT 0
#endif

// __Live_Base_LogInSubUser @ 0x026e50a4 (reached when a user picks "Black Ops II
// online" -> Live_HandleClientSplitscreenSignin) opens the "getting data" popup
// and spins for 40 s waiting for LiveStorage_DoWeHaveAllStats() to go non-zero.
// That flag is a "cloud stats parsed" sentinel (persStatsBuffer + 0xc403); on a
// self-hosted backend with no prior stats blob it is never set, so after 40 s the
// function calls Live_DelayedComError(PLATFORM_DEMONWARE_DISCONNECT) -> the
// "The Call of Duty: Black Ops II server is not available" NOTICE, even though the
// whole auth/LSG/storage handshake completed cleanly.
//
// Force LiveStorage_DoWeHaveAllStats__F17ControllerIndex_t @ 0x026d21d8 to
// `return 1`: patch its first two instructions to `li r3,1 ; blr`. The 40 s loop
// then exits on its first iteration, no NOTICE, and BO2 proceeds online with a
// zeroed stats buffer (a legitimate new-player state - stats fill in from play).
// A predicate stubbed out to `li r3,1 ; blr` (return true).
struct ReturnTrueStub {
    const char *name;
    uint32_t address;      // first instruction
    uint32_t original0;    // expected first instruction
    uint32_t original1;    // expected second instruction
    uint32_t new0;         // instruction to write at word 0 (li/lis r3, N)
    // Wii U relocates RPLs at load time, so any instruction embedding an absolute
    // address differs in memory from the on-disk module. Compare only the bits that
    // are stable: 0xFFFFFFFF for a plain opcode, 0xFFFF0000 to ignore a relocated
    // 16-bit immediate (e.g. `lis r12, <hi(addr)>`).
    uint32_t mask1;
};

constexpr uint32_t PPC_LI_R3_1 = 0x38600001;   // li  r3, 1
constexpr uint32_t PPC_BLR = 0x4e800020;

constexpr ReturnTrueStub RETURN_TRUE_STUBS[] = {
    // Live_HasMultiplayerPrivileges @ 0x026e870c -> return 1.
    //   mulli r0,r3,0x88 / lis r12,0x11bb / addi / lbzx / subic / subfe / blr
    // Returns a single byte at wiiuUserData[idx] + 0x30 that NOTHING in the module
    // ever writes: on retail it comes from the console's NNID/parental-control
    // path, which a self-hosted setup never satisfies, so it stays 0 forever.
    // It is exported to the menu scripts as LUI_CoD_LuaCall_HasMPPrivileges
    // (0x028de020) and gates "Black Ops II online" entirely
    // (CL_Live_StartPrivateParty raises XBOXLIVE_MPNOTALLOWED right after calling
    // it). This is the one stub that is genuinely required.
    // The second word is `lis r12,<hi(addr)>`; the Wii U relocates RPLs at load
    // time (observed 0x11bb -> 0x121a), so mask off the relocated immediate.
    {.name = "mp-privileges", .address = 0x026e870c, .original0 = 0x1c030088,
     .original1 = 0x3d800000, .new0 = PPC_LI_R3_1, .mask1 = 0xffff0000},

    // REMOVED (r33): playlist-unlock, unlock-items, unlock-rank, unlock-buffer,
    // prestige, rank and xp. Those only patched *readers*, so the menus showed
    // everything unlocked and master prestige while the real persistent stats
    // stayed empty - items could be seen but not equipped, the account was still
    // level 1 with 0 unlock tokens, no calling cards and no camos. Unlocking has
    // to be done in the server-side stats blob (mpstatsCompressed, raw-DEFLATE,
    // 50292 bytes) so the game loads genuine values instead of being lied to.
};


// ---------------------------------------------------------------------------
// bdNet IP-discovery probe.
//
// The server sends a reply the console keeps ignoring. Server-side evidence is
// exhausted: the format is taken from this very module
// (bdIPDiscoveryPacketReply::serialize @0x02a24c50), and bdNetImpl::pump reads
// the datagram straight off the UDP socket with no router/decryption in
// between. So read the client's own state instead of guessing.
//
//   bdSingleton<bdNetImpl>::getInstance() caches the object in DAT_10165d44
//   bdNetImpl + 0xbc : status (1 = discovery running, 2 = ready)
//   bdNetImpl + 0xc0 : bdIPDiscoveryClient*
//   bdIPDiscoveryClient + 0x04 : m_serverAddr (bdAddr: 4-byte IP + u16 port)
//   bdIPDiscoveryClient + 0x0c : m_publicAddr (filled in on success)
//   bdIPDiscoveryClient + 0x20 : status  1=RUNNING 2=SUCCESS 3=FAIL 4=ERROR
//   bdIPDiscoveryClient + 0x2c : retry counter
//
// If status ever reaches 2 the reply IS being accepted and something later is
// at fault; if it stays 1 with a climbing retry count the datagram never
// reaches pump(); if it hits 3 the client gave up.
constexpr uint32_t BDNETIMPL_SINGLETON = 0x10165d44;

// The party's copy of the hosted session's security block.
//
// PartyHost_StartPartyComplete (RPL 0x021769ec) memcpy's 0x3d bytes from
// sessionData + 0x11 to partyData + 0x93ac, and sessionData + 0x11 is exactly
// what Session_QoSListenStart_Platform (RPL 0x026b800c) hands to
// bdQoSProbe::listen. So the first 8 bytes here are the bdSecurityID the host
// actually answers QoS probes for - the value to compare against the one the
// server hands out in its session records. A mismatch would explain
// "0/1 good games" for every joiner regardless of NAT, because
// bdQoSProbe::handleRequest drops an unrecognised id without a word.
constexpr uint32_t PARTY_DATA = 0x10371278;
constexpr uint32_t PARTY_SECURITY_ID = PARTY_DATA + 0x93ac;

// The other half of the comparison: g_matchmakingInfo, loaded throughout the
// title as `lis rN,0x11bb ; lwz r3,0x4038(rN)`, so this slot holds a pointer.
// MatchMakingInfo::serialize (RPL 0x02258124) writes the u64 GAME_SECURITY_ID
// from +0x120 - the value the server logs and hands back out in session records.
//
// Reading both matters because uninitialised .bss also reads as zeroes: an
// all-zero party block on its own cannot distinguish "never populated" from
// "wrong address". A real value here alongside zeroes there settles it.
constexpr uint32_t MATCHMAKING_INFO_PTR = 0x11bb4038;
constexpr uint32_t MATCHMAKING_SECURITY_ID_OFFSET = 0x120;

// bdSocketRouter::init (RPL 0x02a13790) builds the bdQoSProbe in place at
// router + 0x58, and the router itself hangs off bdNetImpl + 0xb8 - both already
// reachable from this probe.
//
// bdQoSProbe::acceptPacket (RPL 0x02a26f08) ignores every QoS packet unless
// this + 0x5c == 1, and handleRequest logs "Cannot handle request when in
// un[initialised]" on the same field. Forged probes carrying the advertised
// security id and a zero one were both met with silence, which points at the
// listener never being enabled rather than at any id mismatch - the party
// security block reading all zeroes says the same thing, since
// Session_QoSListenStart is what would have filled it.
constexpr uint32_t ROUTER_QOS_PROBE_OFFSET = 0x58;
constexpr uint32_t QOS_LISTENER_ENABLED_OFFSET = 0x58;
constexpr uint32_t QOS_LISTENER_STATE_OFFSET = 0x5c;

// The gates on the path that actually advertises a public lobby.
//
// Session_ChangeAdvertisedStatus (RPL 0x026b9198) sets +0x140 and raises the
// dirty flag at +0x170; Session_Modify (RPL 0x026b8580) then does nothing at all
// unless +0x174 is non-zero, and picks dwCreateSession over dwUpdateSession on
// +0x17c. PartyHost_Frame drives the first of those every frame.
//
// This is the route a real public match takes - not
// Session_StartHost_Platform_DW, whose branch this plugin forces. Reading the
// four fields says which gate is actually shut.
constexpr uint32_t MM_SHOW_IN_MATCHMAKING_OFFSET = 0x140;
constexpr uint32_t MM_DIRTY_OFFSET = 0x170;
constexpr uint32_t MM_ACTIVE_OFFSET = 0x174;
constexpr uint32_t MM_RECREATE_OFFSET = 0x17c;

// This address is in .bss, while rpl_addr() just offsets from dataAddr and
// assumes everything above 0x10000000 is one contiguous mapping. That holds for
// .rodata and .data; whether .bss is included is up to the loader. Bound-check
// before dereferencing - a stray read here faults the game, not the probe.
const uint8_t *rpl_data_bytes(OSDynLoad_NotifyData rpl, uint32_t addr, uint32_t len) {
    if (addr < 0x10000000u) return nullptr;
    const uint32_t offset = addr - 0x10000000u;
    if (offset > rpl.dataSize || len > rpl.dataSize - offset) return nullptr;
    return reinterpret_cast<const uint8_t *>(rpl.dataAddr + offset);
}

// The diagnostic probe walks live bdNet/matchmaking structures on a 3 s timer by
// chasing raw MEM2 pointers. It faults the whole game if any guess is stale, and
// it has served its purpose (net=, qlsn=, ca=, mm= are all recorded). Ships OFF;
// set to 1 only for a local debugging build.
#ifndef BO2_ENABLE_DIAG_PROBE
#define BO2_ENABLE_DIAG_PROBE 0
#endif

OSThread s_probe_thread;
uint8_t s_probe_stack[16384] __attribute__((aligned(16)));
OSDynLoad_NotifyData s_probe_rpl;
bool s_probe_started = false;

// A mis-guessed offset would hand us a garbage pointer, and faulting inside the
// probe thread takes the whole game down. Only follow something that looks like
// a real, aligned MEM2 allocation.
bool plausible_ptr(uint32_t p) {
    return p >= 0x10000000u && p < 0x50000000u && (p & 3u) == 0u;
}

int probe_entry(int, const char **) {
    char last[224] = {0};
    // 3s * 2400 = two hours. The old 400-tick budget expired after 20 minutes,
    // which is why the toasts went quiet mid-session rather than the state
    // settling down.
    for (int tick = 0; tick < 2400; tick++) {
        OSSleepTicks(OSSecondsToTicks(3));

        const uint8_t *slot = rpl_data_bytes(s_probe_rpl, BDNETIMPL_SINGLETON, 4);
        const uint32_t netimpl =
            slot ? *reinterpret_cast<const uint32_t *>(slot) : 0;
        char msg[224];
        if (!plausible_ptr(netimpl)) {
            snprintf(msg, sizeof(msg), "bdNet: not created yet");
        } else {
            const auto *base = reinterpret_cast<const uint8_t *>(netimpl);
            const uint32_t net_status = *reinterpret_cast<const uint32_t *>(base + 0xbc);
            const uint32_t router = *reinterpret_cast<const uint32_t *>(base + 0xb8);
            const uint32_t ipc = *reinterpret_cast<const uint32_t *>(base + 0xc0);

            // The whole hosting path hangs off this one pointer:
            //   dwCreateSession        -> dwGetLocalCommonAddr
            //   dwGetLocalCommonAddr   -> bdNetImpl::getLocalCommonAddr
            //   bdNetImpl::getLocal... -> bdSocketRouter::getLocalCommonAddr
            //   bdSocketRouter::get... -> just returns *(router + 0x2c)
            // and dwCreateSession returns silently when it is null, which is
            // exactly what "61 FindSessions, 0 CreateSession" looks like.
            uint32_t caddr = 0;
            if (plausible_ptr(router)) {
                caddr = *reinterpret_cast<const uint32_t *>(
                    reinterpret_cast<const uint8_t *>(router) + 0x2c);
            }

            // The id this console answers QoS probes for. All-zero means the
            // party block was never filled in, which is itself the answer.
            char qos[24];
            const uint8_t *sec = rpl_data_bytes(s_probe_rpl, PARTY_SECURITY_ID, 8);
            if (sec == nullptr) {
                snprintf(qos, sizeof(qos), "unmapped");
            } else {
                snprintf(qos, sizeof(qos), "%02x%02x%02x%02x%02x%02x%02x%02x",
                         sec[0], sec[1], sec[2], sec[3], sec[4], sec[5], sec[6], sec[7]);
            }

            // The advertising gates, straight out of g_matchmakingInfo.
            char mmid[64];
            snprintf(mmid, sizeof(mmid), "none");
            const uint8_t *slot_mm = rpl_data_bytes(s_probe_rpl, MATCHMAKING_INFO_PTR, 4);
            if (slot_mm != nullptr) {
                const uint32_t mm = *reinterpret_cast<const uint32_t *>(slot_mm);
                if (plausible_ptr(mm)) {
                    const auto *m = reinterpret_cast<const uint8_t *>(mm);
                    const auto field = [m](uint32_t off) {
                        return *reinterpret_cast<const uint32_t *>(m + off);
                    };
                    snprintf(mmid, sizeof(mmid), "adv=%u dirty=%u act=%u recr=%u",
                             field(MM_SHOW_IN_MATCHMAKING_OFFSET),
                             field(MM_DIRTY_OFFSET),
                             field(MM_ACTIVE_OFFSET),
                             field(MM_RECREATE_OFFSET));
                }
            }

            // What the local bdCommonAddr actually contains.
            //
            // Live_GetLocalNatType (RPL 0x026e2370) returns a hardcoded 3 - which
            // the menu renders as "NAT: Strict" - whenever it cannot get a common
            // address, and otherwise returns bdCommonAddr::getNATType, i.e.
            // *(this + 0x1c). Three players on three networks all reading Strict
            // is that default, not their routers.
            //
            // One unpopulated common address would also account for the traversal
            // packets carrying 0.255.0.255:0 and for the party security block
            // reading zero, so print the type plus the first bytes of the object.
            char cinfo[48];
            snprintf(cinfo, sizeof(cinfo), "nil");
            if (plausible_ptr(caddr)) {
                const auto *ca = reinterpret_cast<const uint8_t *>(caddr);
                const uint32_t nat = *reinterpret_cast<const uint32_t *>(ca + 0x1c);
                snprintf(cinfo, sizeof(cinfo), "nat=%u [%02x%02x%02x%02x %02x%02x%02x%02x]",
                         nat, ca[0], ca[1], ca[2], ca[3], ca[4], ca[5], ca[6], ca[7]);
            }

            // Is the QoS listener actually running? Two fields decide whether a
            // probe is even looked at.
            char qstate[24];
            snprintf(qstate, sizeof(qstate), "norouter");
            if (plausible_ptr(router)) {
                const uint32_t probe_obj = router + ROUTER_QOS_PROBE_OFFSET;
                const auto *q = reinterpret_cast<const uint8_t *>(probe_obj);
                const uint32_t enabled = *reinterpret_cast<const uint32_t *>(
                    q + QOS_LISTENER_ENABLED_OFFSET);
                const uint32_t state = *reinterpret_cast<const uint32_t *>(
                    q + QOS_LISTENER_STATE_OFFSET);
                snprintf(qstate, sizeof(qstate), "%u/%u", enabled, state);
            }

            if (plausible_ptr(ipc)) {
                const auto *c = reinterpret_cast<const uint8_t *>(ipc);
                const uint32_t st = *reinterpret_cast<const uint32_t *>(c + 0x20);
                snprintf(msg, sizeof(msg), "net=%u qlsn=%s %s ca=%s",
                         net_status, qstate, mmid, cinfo);
            } else {
                snprintf(msg, sizeof(msg), "net=%u qlsn=%s %s ca=%s ipdisc=none",
                         net_status, qstate, mmid, cinfo);
            }
        }
        if (strcmp(msg, last) != 0) {
            snprintf(last, sizeof(last), "%s", msg);
            DEBUG_FUNCTION_LINE("%s", msg);
            ShowNotification(msg);
        }
    }
    return 0;
}

void start_bdnet_probe(OSDynLoad_NotifyData rpl) {
    if (s_probe_started) return;
    s_probe_started = true;
    s_probe_rpl = rpl;
    if (OSCreateThread(&s_probe_thread, probe_entry, 0, nullptr,
                       s_probe_stack + sizeof(s_probe_stack), sizeof(s_probe_stack),
                       16, OS_THREAD_ATTRIB_AFFINITY_ANY)) {
        OSResumeThread(&s_probe_thread);
    }
}

bool s_bo2_patch_done = false;

// ---------------------------------------------------------------------------
// Diagnostic probe: is the playlist table actually populated?
//
// "Find a match" stays greyed out even with MP privileges granted, and the only
// way to see the playlist list in-game is through that very button. So read the
// table directly instead. Playlist_GetPlaylistCount (0x024b015c) walks 200 slots
// of 0x60 bytes starting at 0x1140f848 + 0x3dc and counts the non-zero ones;
// this mirrors that, read-only.
//
// rpl_addr() maps data addresses correctly even though the module is relocated
// (verified: 0x11bb2c90 resolved to the live 0x121a2c90), so this is safe.
// replace_instruction() reports success by reading the word back immediately after
// KernelCopyData. For code that the title is actively executing - notably
// Live_HasMultiplayerPrivileges, which the menu Lua polls constantly - that
// read-back can still be served from a warm cache line and the helper then reports
// failure even though the target address was correct. Validate the address *before*
// writing (that is the part that actually keeps us safe), then write and explicitly
// push the change out to memory and out of the instruction cache.
bool force_patch(uint32_t *addr, uint32_t original, uint32_t replacement,
                 uint32_t mask = 0xffffffff) {
    const uint32_t current = *addr;
    if (current == replacement) return true;            // already patched this launch
    if ((current & mask) != (original & mask)) return false;  // not what we expect

    // Hand replace_instruction the word we actually read, not the (possibly masked)
    // template: it re-checks for an exact match before writing, so passing
    // `original` would make it silently refuse whenever the immediate was relocated.
    replace_instruction(addr, current, replacement);
    DCFlushRange(addr, sizeof(replacement));
    ICInvalidateRange(addr, sizeof(replacement));
    // Report what really happened rather than assuming the write landed.
    return *addr == replacement;
}
}

void reset_bo2_auth_patch() { s_bo2_patch_done = false; }

void patch_bo2_auth() {
    if (s_bo2_patch_done) return;
    if (!Config::connect_to_network) return;

    // Don't gate on the title id. patch_bo2_auth() only runs when a
    // *.demonware.net host resolves (dns_hooks.cpp), which on Wii U only BO2
    // does, and the RPL-name plus per-patch opcode checks below are the real
    // guard. A title-id list only adds a failure mode where a wrong constant for
    // one region silently skips patching - and then the RSA-verify path runs
    // unpatched against our unsigned reply, which is a hard fault, not a NOTICE.
    const uint64_t title_id = OSGetTitleID();
    const char *region = title_id == BO2_USA_TITLE_ID   ? "USA"
                         : title_id == BO2_EUR_TITLE_ID ? "EUR"
                                                        : "other";
    DEBUG_FUNCTION_LINE("BO2 auth patch: title_id=%016llx (%s)", title_id, region);

    const auto multiplayer = search_for_rpl("t6mp_cafef_rpl.rpl"sv);
    if (!multiplayer) {
        DEBUG_FUNCTION_LINE("BO2 auth patch skipped: multiplayer RPL not loaded yet");
        return;
    }

    // Confirm this really is a build we have addresses for before touching
    // anything: the RSA-verify site must hold the exact bne we expect.
    {
        const uint32_t rsa_now =
            *static_cast<const uint32_t *>(rpl_addr(*multiplayer, RSA_VERIFY_BRANCH));
        if (rsa_now != ORIGINAL_BNE && rsa_now != BYPASS_BRANCH) {
            DEBUG_FUNCTION_LINE("BO2 auth patch skipped: RSA site is %08x, not a known build",
                                rsa_now);
            ShowNotification("BO2: unrecognised game build, not patching");
            return;
        }
    }

    auto *branch = static_cast<uint32_t *>(rpl_addr(*multiplayer, RSA_VERIFY_BRANCH));
    const bool rsa_changed = replace_instruction(branch, ORIGINAL_BNE, BYPASS_BRANCH);
    const bool rsa_ok = rsa_changed || *branch == BYPASS_BRANCH;
    if (!rsa_ok) {
        DEBUG_FUNCTION_LINE("BO2 auth patch skipped: unexpected instruction %08x", *branch);
        ShowNotification("BO2: authentication patch address mismatch");
        s_bo2_patch_done = true;  // don't spam every DNS lookup
        return;
    }

    auto *magic_branch = static_cast<uint32_t *>(rpl_addr(*multiplayer, TICKET_MAGIC_BRANCH));
    const bool magic_changed = replace_instruction(magic_branch, ORIGINAL_MAGIC_BNE, BYPASS_MAGIC_CHECK);
    const bool magic_ok = magic_changed || *magic_branch == BYPASS_MAGIC_CHECK;
    if (!magic_ok) {
        DEBUG_FUNCTION_LINE("BO2 ticket patch skipped: unexpected instruction %08x", *magic_branch);
        ShowNotification("BO2: ticket patch address mismatch");
        s_bo2_patch_done = true;
        return;
    }

    // Neither relaxing the required mask (r17/r18, 0x1BEE -> 0x6) nor restoring it
    // (r19) works: relaxing opens the menu while the online subsystems are still
    // "not ready", so every button re-checks its own preconditions and greys
    // itself out; restoring leaves the mask incomplete and the title eventually
    // errors out. Instead, make the *computed* mask complete by NOP-ing the
    // conditional branches that skip each `ori` in
    // Live_GetConnectivityInformation. Every consumer of the mask - not just
    // __IsDemonwareFetchingDone - then sees a consistent "everything ready"
    // state, which is what the individual menu buttons test.
    int connectivity_changed = 0;
    for (const auto &patch : CONNECTIVITY_BRANCHES) {
        auto *insn = static_cast<uint32_t *>(rpl_addr(*multiplayer, patch.address));
        const uint32_t before = *insn;
        if (!force_patch(insn, patch.original, PPC_NOP)) {
            DEBUG_FUNCTION_LINE("BO2 connectivity patch skipped at %08x: found %08x, expected %08x",
                                patch.address, before, patch.original);
            ShowNotification("BO2: connectivity patch address mismatch");
            s_bo2_patch_done = true;
            return;
        }
        if (before != PPC_NOP) connectivity_changed++;
    }

    if (FORCE_ADVERTISE_BRANCH) {
        auto *insn = static_cast<uint32_t *>(rpl_addr(*multiplayer, ADVERTISE_BRANCH));
        const uint32_t before = *insn;
        if (force_patch(insn, ADVERTISE_BRANCH_ORIGINAL, PPC_NOP)) {
            if (before != PPC_NOP) {
                DEBUG_FUNCTION_LINE("BO2: session advertising forced at %08x", ADVERTISE_BRANCH);
                ShowNotification("BO2: session advertising forced");
            }
        } else {
            DEBUG_FUNCTION_LINE("BO2 advertise patch skipped at %08x: found %08x, expected %08x",
                                ADVERTISE_BRANCH, before, ADVERTISE_BRANCH_ORIGINAL);
            ShowNotification("BO2: advertise patch address mismatch");
        }
    } else {
        // The alternative route: open both m_active gates so the game's own
        // Session_Modify path can run (doUpdate first, then the gate inside
        // Session_Modify itself).
        struct Gate { uint32_t addr; uint32_t original; };
        const Gate gates[] = {
            {DOUPDATE_GATE, DOUPDATE_GATE_ORIGINAL},
            {SESSION_MODIFY_GATE, SESSION_MODIFY_GATE_ORIGINAL},
        };
        for (const auto &g : gates) {
            auto *insn = static_cast<uint32_t *>(rpl_addr(*multiplayer, g.addr));
            const uint32_t before = *insn;
            if (force_patch(insn, g.original, PPC_NOP)) {
                if (before != PPC_NOP) {
                    DEBUG_FUNCTION_LINE("BO2: m_active gate opened at %08x", g.addr);
                }
            } else {
                DEBUG_FUNCTION_LINE("BO2 m_active gate skipped at %08x: found %08x, expected %08x",
                                    g.addr, before, g.original);
                ShowNotification("BO2: advertise gate address mismatch");
            }
        }
    }

    // Rebind bdNet to a forwardable port. Off by default: only needed on a
    // shared-IPv4 line where UDP 3074 cannot be forwarded (see BDNET_PORT_INSN).
    if (BO2_REBIND_BDNET_PORT) {
        auto *insn = static_cast<uint32_t *>(rpl_addr(*multiplayer, BDNET_PORT_INSN));
        const uint32_t before = *insn;
        if (force_patch(insn, BDNET_PORT_ORIGINAL, BDNET_PORT_PATCHED)) {
            if (before != BDNET_PORT_PATCHED) {
                DEBUG_FUNCTION_LINE("BO2: bdNet port moved to %u", BDNET_PORT_NEW);
                char msg[64];
                snprintf(msg, sizeof(msg), "BO2: bdNet port -> %u (forward UDP %u)",
                         BDNET_PORT_NEW, BDNET_PORT_NEW);
                ShowNotification(msg);
            }
        } else {
            DEBUG_FUNCTION_LINE("BO2 port patch skipped at %08x: found %08x, expected %08x",
                                BDNET_PORT_INSN, before, BDNET_PORT_ORIGINAL);
            ShowNotification("BO2: bdNet port patch address mismatch");
        }
    }

    int stubs_changed = 0;
    for (const auto &stub : RETURN_TRUE_STUBS) {
        auto *i0 = static_cast<uint32_t *>(rpl_addr(*multiplayer, stub.address));
        auto *i1 = static_cast<uint32_t *>(rpl_addr(*multiplayer, stub.address + 4));
        const uint32_t b0 = *i0;
        const uint32_t b1 = *i1;
        const uint32_t want0 = stub.new0;
        // Cheap sanity net: every replacement must be `li r3,N` (0x386000xx) or
        // `lis r3,N` (0x3c60xxxx). A mis-ordered initialiser once made this write
        // 0xffff0000 into Live_HasMultiplayerPrivileges, corrupting the function.
        if ((want0 & 0xffff0000) != 0x38600000 && (want0 & 0xffff0000) != 0x3c600000) {
            DEBUG_FUNCTION_LINE("BO2 %s: refusing bogus replacement %08x", stub.name, want0);
            ShowNotification("BO2: internal patch table error");
            s_bo2_patch_done = true;
            return;
        }
        const bool p0 = force_patch(i0, stub.original0, want0);
        const bool p1 = force_patch(i1, stub.original1, PPC_BLR, stub.mask1);
        if (!p0 || !p1) {
            // Report exactly what was found so the failure can be diagnosed from the
            // console instead of guessed at: a wrong address shows unrelated opcodes,
            // whereas a rejected write shows the expected ones.
            char msg[128];
            snprintf(msg, sizeof(msg), "BO2 %s: got %08x/%08x want %08x/%08x",
                     stub.name, b0, b1, stub.original0, stub.original1);
            DEBUG_FUNCTION_LINE("%s", msg);
            ShowNotification(msg);
            // Deliberately do NOT bail out: the other patches are still worth having.
            continue;
        }
        // Confirm the write actually stuck, and say so.
        {
            char msg[96];
            snprintf(msg, sizeof(msg), "BO2 %s patched -> %08x/%08x", stub.name, *i0, *i1);
            DEBUG_FUNCTION_LINE("%s", msg);
            ShowNotification(msg);
        }
        if (b0 != want0 || b1 != PPC_BLR) stubs_changed++;
    }

    DEBUG_FUNCTION_LINE("BO2 patches applied: RSA + ticket + %d connectivity bits + %d stubs",
                        connectivity_changed, stubs_changed);
    if (rsa_changed || magic_changed || connectivity_changed > 0 || stubs_changed > 0) {
        ShowNotification("BO2: authentication patch applied");
    }
    if (BO2_ENABLE_DIAG_PROBE) {
        start_bdnet_probe(*multiplayer);
    }
    s_bo2_patch_done = true;
}

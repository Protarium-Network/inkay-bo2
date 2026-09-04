#pragma once

void patch_bo2_auth();

// Re-arm the BO2 patch for a fresh application launch (the WUMS module
// persists across launches; the multiplayer RPL is reloaded at a new address
// each time BO2 starts).
void reset_bo2_auth_patch();

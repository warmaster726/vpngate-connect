#ifndef VPNGATE_BRIDGING_HEADER_H
#define VPNGATE_BRIDGING_HEADER_H

#include "GeneratedPluginRegistrant.h"

// Exported by crates/vpngate-bridge (libvpngate_bridge.a)
char *vpngate_json_call(const char *method, const char *params_json);
char *vpngate_drain_progress_json(void);
void vpngate_free_string(char *ptr);

#endif

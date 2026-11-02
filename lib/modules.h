#pragma once

#include <stdlib.h>
#include <stdint.h>

int run_probe_ap(void);
int run_probe_client(void);
int run_probe_carpet(void);
int run_attack_deauth_unicast_single(void);
int run_attack_deauth_unicast_flood(void);
int run_attack_deauth_broadcast_single(void);
int run_attack_deauth_broadcast_flood(void);
int run_attack_deauth_serial_single(void);
int run_attack_deauth_serial_flood(void);
int run_attack_deauth_roster_single(void);
int run_attack_deauth_roster_flood(void);
int run_attack_deauth_carpet_single(void);
int run_attack_deauth_carpet_flood(void);

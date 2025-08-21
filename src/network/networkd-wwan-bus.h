/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

int manager_notify_mm_bus_connected(Manager *manager);
int manager_match_modemmanager_signals(Manager *manager);

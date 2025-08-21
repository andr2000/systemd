/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-map-properties.h"
#include "bus-match.h"
#include "bus-parse-xml.h"
#include "bus-util.h"
#include "networkd-manager.h"
#include "networkd-wwan-bus.h"
#include "networkd-wwan.h"

/* From ModemManager-enums.h */
typedef enum {
    MM_BEARER_IP_FAMILY_NONE    = 0,
    MM_BEARER_IP_FAMILY_IPV4    = 1 << 0,
    MM_BEARER_IP_FAMILY_IPV6    = 1 << 1,
    MM_BEARER_IP_FAMILY_IPV4V6  = 1 << 2,
    MM_BEARER_IP_FAMILY_ANY     = 0xFFFFFFFF
} MMBearerIpFamily;

typedef enum {
    MM_BEARER_TYPE_UNKNOWN        = 0,
    MM_BEARER_TYPE_DEFAULT        = 1,
    MM_BEARER_TYPE_DEFAULT_ATTACH = 2,
    MM_BEARER_TYPE_DEDICATED      = 3
} MMBearerType;

static int map_name(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        Bearer *b = ASSERT_PTR(userdata);
        const char *s;
        int r;

        assert(m);

        /*
         * If name is already set - do not wipe it on disconnect, so
         * we can work with link and other code which relies on the
         * interface name.
         */
        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        if (b->name && strlen(b->name))
                return 0;

        return bearer_set_name(b, s);
}

static int map_dns(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        Bearer *b = ASSERT_PTR(userdata);
        union in_addr_union a;
        const char *s;
        int family, r;

        assert(m);

        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        r = in_addr_from_string_auto(s, &family, &a);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(b->dns, b->n_dns + 1))
                return -ENOMEM;

        b->dns[b->n_dns++] = (struct in_addr_data) {
                .family = family,
                .address = a,
        };

        return 0;
}

static int map_in_addr(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata, int family) {
        union in_addr_union *addr = ASSERT_PTR(userdata);
        const char *s;
        int r;

        assert(m);

        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        return in_addr_from_string(family, s, addr);
}

static int map_in4(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_in_addr(bus, member, m, error, userdata, AF_INET);
}

static int map_in6(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_in_addr(bus, member, m, error, userdata, AF_INET6);
}

static int map_ip4_config(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        static const struct bus_properties_map map[] = {
                { "method",  "u", NULL,    offsetof(Bearer, ip4_method)    },
                { "address", "s", map_in4, offsetof(Bearer, ip4_address)   },
                { "prefix",  "u", NULL,    offsetof(Bearer, ip4_prefixlen) },
                { "dns1",    "s", map_dns, 0,                              },
                { "dns2",    "s", map_dns, 0,                              },
                { "dns3",    "s", map_dns, 0,                              },
                { "gateway", "s", map_in4, offsetof(Bearer, ip4_gateway)   },
                { "mtu",     "u", NULL,    offsetof(Bearer, ip4_mtu)       },
                {}
        };

        Bearer *b = ASSERT_PTR(userdata);

        /*
         * FIXME: Only default-attach bearer has ip-type field,
         * so there is no chance to detect IP type in this one.
         */

        b->ip_type = ADDRESS_FAMILY_IPV4;

        return bus_message_map_all_properties(m, map, 0, error, userdata);
}

static int map_ip6_config(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        static const struct bus_properties_map map[] = {
                { "method",  "u", NULL,    offsetof(Bearer, ip6_method)    },
                { "address", "s", map_in6, offsetof(Bearer, ip6_address)   },
                { "prefix",  "u", NULL,    offsetof(Bearer, ip6_prefixlen) },
                { "dns1",    "s", map_dns, 0,                              },
                { "dns2",    "s", map_dns, 0,                              },
                { "dns3",    "s", map_dns, 0,                              },
                { "gateway", "s", map_in6, offsetof(Bearer, ip6_gateway)   },
                { "mtu",     "u", NULL,    offsetof(Bearer, ip6_mtu)       },
                {}
        };

        return bus_message_map_all_properties(m, map, 0, error, userdata);
}

static int map_ip_type(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        AddressFamily *ip_type = ASSERT_PTR(userdata);
        unsigned u;
        int r;

        assert(m);


        r = sd_bus_message_read_basic(m, 'u', &u);
        if (r < 0)
                return r;

        switch (u) {
        case MM_BEARER_IP_FAMILY_NONE:
                *ip_type = ADDRESS_FAMILY_NO;
                break;
        case MM_BEARER_IP_FAMILY_IPV4:
                *ip_type = ADDRESS_FAMILY_IPV4;
                break;
        case MM_BEARER_IP_FAMILY_IPV6:
                *ip_type = ADDRESS_FAMILY_IPV6;
                break;
        case MM_BEARER_IP_FAMILY_IPV4V6:
                *ip_type = ADDRESS_FAMILY_YES;
                break;
        }

        return 0;
}

static int map_properties(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        static const struct bus_properties_map map[] = {
                { "apn",     "s", NULL,        offsetof(Bearer, apn)     },
                { "ip-type", "u", map_ip_type, offsetof(Bearer, ip_type) },
                {}
        };

        return bus_message_map_all_properties(m, map, BUS_MAP_STRDUP, error, userdata);
}

static int bus_message_check_properties(
                sd_bus_message *m,
                const struct bus_properties_map *map,
                sd_bus_error *error,
                int *found_cnt) {

        int r;

        assert(m);
        assert(map);

        *found_cnt = 0;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
        if (r < 0) {
                return bus_log_parse_error_debug(r);
        }

        while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
                const struct bus_properties_map *prop;
                const char *member;
                unsigned i;

                r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &member);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                for (i = 0, prop = NULL; map[i].member; i++)
                        if (streq(map[i].member, member)) {
                                prop = &map[i];
                                break;
                        }

                r = sd_bus_message_skip(m, "v");
                if (r < 0)
                        return bus_log_parse_error_debug(r);
                if (prop)
                        (*found_cnt)++;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return bus_log_parse_error_debug(r);
        }
        if (r < 0)
                return bus_log_parse_error_debug(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        return r;
}

static int bearer_get_all_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        static const struct bus_properties_map map[] = {
                { "Interface",  "s",     map_name,       0                           },
                { "BearerType", "u",     NULL,           offsetof(Bearer, type),     },
                { "Connected",  "b",     NULL,           offsetof(Bearer, connected) },
                { "Ip4Config",  "a{sv}", map_ip4_config, 0,                          },
                { "Ip6Config",  "a{sv}", map_ip6_config, 0,                          },
                { "Properties", "a{sv}", map_properties, 0,                          },
                {}
        };

        Bearer *b = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int r;
        int found_cnt;

        assert(message);

        log_error("%s:%d %s path %s", __FILE__, __LINE__, __func__, b->path);
        b->slot = sd_bus_slot_unref(b->slot);

        e = sd_bus_message_get_error(message);
        if (e) {
                bool removed = false;

                if (sd_bus_error_has_name(e, SD_BUS_ERROR_UNKNOWN_METHOD))
                        /* The path is already removed? */
                        removed = true;

                r = sd_bus_error_get_errno(e);
                log_full_errno(removed ? LOG_DEBUG : LOG_WARNING, r,
                               "Could not get properties of bearer \"%s\": %s",
                               b->path, bus_error_message(e, r));

                bearer_drop(b);
                return 0;
        }

        /* skip name: string "org.freedesktop.ModemManager1.Bearer" */
        sd_bus_message_skip(message, "s");
        r = bus_message_check_properties(message, map, ret_error, &found_cnt);
        if (r < 0)
                return log_warning_errno(r, "Failed to count properties of bearer \"%s\": %s", b->path, bus_error_message(ret_error, r));

        log_error("%s found %d properties changed\n", __func__, found_cnt);
        if (!found_cnt)
                return 0;

        r = sd_bus_message_rewind(message, true);
        if (r < 0)
                return log_warning_errno(r, "Failed to rewind properties of bearer \"%s\"", b->path);
        /* skip name: string "org.freedesktop.ModemManager1.Bearer" */
        sd_bus_message_skip(message, "s");

        r = bus_message_map_all_properties(message, map, BUS_MAP_BOOLEAN_AS_BOOL, ret_error, b);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse properties of bearer \"%s\": %s", b->path, bus_error_message(ret_error, r));

        /*
         * aleksander0m: You should ignore those bearers with type
         * default-attach and without any interface reported.
         */
        if (b->type == MM_BEARER_TYPE_DEFAULT_ATTACH)
                return log_warning_errno(-EINVAL, "Skip Bearer of type MM_BEARER_TYPE_DEFAULT_ATTACH \"%s\"", b->path);

        log_error("Connected: %d interface %s", b->connected, b->name);
        return bearer_update_link(b);
}

static int bearer_initialize(Bearer *b) {
        int r;

        assert(b);
        assert(b->manager);
        assert(sd_bus_is_ready(b->manager->bus) > 0);
        assert(b->path);

        b->slot = sd_bus_slot_unref(b->slot);

        r = sd_bus_call_method_async(
                        b->manager->bus,
                        &b->slot,
                        "org.freedesktop.ModemManager1",
                        b->path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        bearer_get_all_handler,
                        b,
                        "s", "org.freedesktop.ModemManager1.Bearer");
        if (r < 0)
                return log_warning_errno(r, "Could not get properties of bearer \"%s\": %m", b->path);

        return 0;
}

static int bearer_new_and_initialize(Manager *manager, const char *path) {
        _cleanup_(bearer_freep) Bearer *b = NULL;
        int r;

        assert(manager);
        assert(path);

        r = bearer_new(manager, path, &b);
        if (r < 0)
                return log_warning_errno(r, "Failed to allocate new bearer \"%s\": %m", path);

        r = bearer_initialize(b);
        if (r < 0)
                return r;

        TAKE_PTR(b);
        return 0;
}

static int bearer_save_path(const char *path, void *userdata) {
        Set **set = ASSERT_PTR(userdata);

        return set_put_strdup(set, path);
}

static int enumerate_bearer_handler(sd_bus_message *message, void *userdata,
                                    sd_bus_error *ret_error) {
        static const XMLIntrospectOps ops = {
                .on_path = bearer_save_path,
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_set_free_ Set *paths = NULL;
        const sd_bus_error *e;
        const char *xml, *path;
        int r;

        assert(message);

        e = sd_bus_message_get_error(message);
        if (e) {
                int level = LOG_WARNING;

                if (sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN))
                        /* ModemManager is not started yet. */
                        level = LOG_DEBUG;

                r = sd_bus_error_get_errno(e);
                log_full_errno(level, r, "Could not get bearers: %s", bus_error_message(e, r));
                return 0;
        }

        r = sd_bus_message_read(message, "s", &xml);
        if (r < 0)
                return bus_log_parse_error(r);

        r = parse_xml_introspect("/org/freedesktop/ModemManager1/Bearer", xml, &ops, &paths);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse DBus introspect XML, ignoring: %m");
                return 0;
        }

        SET_FOREACH(path, paths) {
                if (streq(path, "/org/freedesktop/ModemManager1/Bearer"))
                        continue;

                log_error("XXX New bearer at %s, manager %p\n", path, manager);
                (void) bearer_new_and_initialize(manager, path);
        }

        return 0;
}

static int enumerate_bearers(Manager *manager) {
        int r;

        log_error("%s", __func__);
        assert(manager);
        assert(sd_bus_is_ready(manager->bus) > 0);

        r = sd_bus_call_method_async(
                        manager->bus,
                        NULL,
                        "org.freedesktop.ModemManager1",
                        "/org/freedesktop/ModemManager1/Bearer",
                        "org.freedesktop.DBus.Introspectable",
                        "Introspect",
                        enumerate_bearer_handler,
                        manager,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get bearers: %m");

        return 0;
}

static int bearer_properties_changed_handler(sd_bus_message *message,
                                             void *userdata,
                                             sd_bus_error *error) {
        Manager *manager = ASSERT_PTR(userdata);
        const char *path;
        Bearer *b;

        assert(message);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        if (streq(path, "/org/freedesktop/ModemManager1/Bearer"))
                return 0;

        if (bearer_get_by_path(manager, path, &b) < 0) {
                /* New bearer. */
                (void) bearer_new_and_initialize(manager, path);
                return 0;
        }

        if (b->slot) {
                /* Not initialized yet. Re-initialize it. */
                (void) bearer_initialize(b);
                return 0;
        }

        (void) bearer_get_all_handler(message, b, error);
        return 0;
}

static int bearer_signals(Manager *manager) {
        static const char *expression =
                "type='signal',"
                "sender='org.freedesktop.ModemManager1',"
                "path_namespace='/org/freedesktop/ModemManager1/Bearer',"
                "interface='org.freedesktop.DBus.Properties',"
                "member='PropertiesChanged'";
        int r;

        assert(manager);
        assert(manager->bus);

        r = sd_bus_add_match_async(manager->bus, NULL, expression,
                                   bearer_properties_changed_handler, NULL,
                                   manager);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PropertiesChanged in ModemManager bearers: %m");

        return 0;
}

static int modemmanager_service_changed(sd_bus_message *message, void *userdata,
                                        sd_bus_error *error) {
        const char *name;
        const char *new_owner;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "sss", &name, NULL, &new_owner);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq(name, "org.freedesktop.ModemManager1"))
                return 0;

        if (strlen(new_owner)) {
                log_error("------------------------------------------ ModemManager alive");
                /* Enumerate and create all bearers */
        } else {
                log_error("------------------------------------------ ModemManager dead");
                /* Remove all bearers */
        }

        return 0;
}

int manager_match_modemmanager_signals(Manager *manager) {
        static const char *expression =
                "type='signal',"
                "sender='org.freedesktop.DBus',"
                "path_namespace='/org/freedesktop/DBus',"
                "interface='org.freedesktop.DBus',"
                "member='NameOwnerChanged'";
        int r;

        assert(manager);
        assert(manager->bus);

        r = sd_bus_add_match_async(manager->bus, NULL, expression,
                                   modemmanager_service_changed, NULL, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to request signal for NameOwnerChanged");

        return 0;
}

static int listnames_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *m = ASSERT_PTR(userdata);
        char **names = NULL;
        char **p;
        int r;
        bool found;

        assert(message);

        m->slot = sd_bus_slot_unref(m->slot);

        r = sd_bus_message_read_strv(message, &names);
        if (r < 0)
                return bus_log_parse_error(r);

        found = false;
        for (p = names; *p != NULL; p++) {
                if (streq(*p, "org.freedesktop.ModemManager1")) {
                        found = true;
                }
        }

        /* If not found then wait for NameOwnerChanged signal */
        if (!found)
                return 0;

        log_info("wwan: ModemManager is available");
        return 0;
}

int manager_notify_mm_bus_connected(Manager *m) {
        int r;

        /*
         * Called on D-Bus connected.
         * Check if ModemManager is available. If it is then initialize.
         * If not then wait for the serivce to be available.
         */
        assert(m);
        assert(sd_bus_is_ready(m->bus) > 0);

        r = sd_bus_call_method_async(m->bus, &m->slot,
                                 "org.freedesktop.DBus",
                                 "/org/freedesktop/DBus",
                                 "org.freedesktop.DBus",
                                 "ListNames",
                                 listnames_handler, m, NULL, NULL);
        if (r < 0)
            return log_warning_errno(r, "Could not LsitNames: %m");

        return 0;
}

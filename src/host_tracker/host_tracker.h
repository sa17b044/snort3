//--------------------------------------------------------------------------
// Copyright (C) 2015-2020 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// host_tracker.h author Steve Chew <stechew@cisco.com>

#ifndef HOST_TRACKER_H
#define HOST_TRACKER_H

// The HostTracker class holds information known about a host (may be from
// configuration or dynamic discovery).  It provides a thread-safe API to
// set/get the host data.

#include <cstring>
#include <mutex>
#include <list>
#include <set>
#include <vector>

#include "framework/counts.h"
#include "host_cache_allocator.h"
#include "main/snort_types.h"
#include "main/thread.h"
#include "network_inspectors/appid/application_ids.h"
#include "protocols/protocol_ids.h"
#include "protocols/vlan.h"
#include "time/packet_time.h"

struct HostTrackerStats
{
    PegCount service_adds;
    PegCount service_finds;
};

extern THREAD_LOCAL struct HostTrackerStats host_tracker_stats;

namespace snort
{
#define INFO_SIZE 32
#define MAC_SIZE 6
extern const uint8_t zero_mac[MAC_SIZE];

struct HostMac
{
    HostMac() : ttl(0), primary(0), last_seen(0)
    { memset(mac, 0, MAC_SIZE); }

    HostMac(uint8_t p_ttl, const uint8_t* p_mac, uint8_t p_primary, uint32_t p_last_seen)
        : ttl(p_ttl), primary(p_primary), last_seen (p_last_seen) { memcpy(mac, p_mac, MAC_SIZE); }

    // the type and order below should match logger's serialization
    uint8_t ttl;
    uint8_t mac[MAC_SIZE];
    uint8_t primary;
    uint32_t last_seen;
};

struct HostApplicationInfo
{
    HostApplicationInfo() = default;
    HostApplicationInfo(const char *ver, const char *ven);
    char vendor[INFO_SIZE] = { 0 };
    char version[INFO_SIZE] = { 0 };
};

typedef HostCacheAllocIp<HostApplicationInfo> HostAppInfoAllocator;

struct HostApplication
{
    HostApplication() = default;
    HostApplication(Port pt, IpProtocol pr, AppId ap, bool in, uint32_t ht = 0, uint32_t ls = 0) :
        port(pt), proto(pr), appid(ap), inferred_appid(in), hits(ht), last_seen(ls) { }
    HostApplication(const HostApplication& ha): port(ha.port), proto(ha.proto), appid(ha.appid),
        inferred_appid(ha.inferred_appid), hits(ha.hits), last_seen(ha.last_seen), info(ha.info),
        payloads(ha.payloads) { }
    HostApplication& operator=(const HostApplication& ha)
    {
        port = ha.port;
        proto = ha.proto;
        appid = ha.appid;
        inferred_appid = ha.inferred_appid;
        hits = ha.hits;
        last_seen = ha.last_seen;
        info = ha.info;
        payloads = ha.payloads;
        return *this;
    }

    Port port = 0;
    IpProtocol proto;
    AppId appid = APP_ID_NONE;
    bool inferred_appid = false;
    uint32_t hits = 0;
    uint32_t last_seen = 0;
    char user[INFO_SIZE] = { 0 };

    std::vector<HostApplicationInfo, HostAppInfoAllocator> info;
    std::vector<AppId, HostCacheAllocIp<AppId>> payloads;
};

struct HostClient
{
    HostClient() = default;
    HostClient(AppId clientid, const char *ver, AppId ser);
    AppId id;
    char version[INFO_SIZE] = { 0 };
    AppId service;
};

struct DeviceFingerprint
{
    DeviceFingerprint(uint32_t id, uint32_t type, bool jb, const char* dev);
    uint32_t fpid;
    uint32_t fp_type;
    bool jail_broken;
    char device[INFO_SIZE] = { 0 };
};

enum HostType : std::uint32_t
{
    HOST_TYPE_HOST = 0,
    HOST_TYPE_ROUTER,
    HOST_TYPE_BRIDGE,
    HOST_TYPE_NAT,
    HOST_TYPE_LB
};

#define MIN_BOOT_TIME    10
#define MIN_TTL_DIFF     16

typedef HostCacheAllocIp<HostMac> HostMacAllocator;
typedef HostCacheAllocIp<HostApplication> HostAppAllocator;
typedef HostCacheAllocIp<HostClient> HostClientAllocator;
typedef HostCacheAllocIp<DeviceFingerprint> HostDeviceFpAllocator;

class SO_PUBLIC HostTracker
{
public:
    HostTracker() : hops(-1)
    {
        last_seen = nat_count_start = (uint32_t) packet_time();
        last_event = -1;
    }

    void update_last_seen();
    uint32_t get_last_seen() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return last_seen;
    }

    void update_last_event(uint32_t time = 0);
    uint32_t get_last_event() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return last_event;
    }

    std::vector<uint16_t, HostCacheAllocIp<uint16_t>> get_network_protos()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return network_protos;
    }

    std::vector<uint8_t, HostCacheAllocIp<uint8_t>> get_xport_protos()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return xport_protos;
    }

    void set_host_type(HostType rht)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        host_type = rht;
    }

    HostType get_host_type() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return host_type;
    }

    uint8_t get_hops()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return hops;
    }

    void update_hops(uint8_t h)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        hops = h;
    }

    // Returns true if a new mac entry is added, false otherwise
    bool add_mac(const uint8_t* mac, uint8_t ttl, uint8_t primary);

    // Returns true if a mac entry TTL is updated and decreased, false otherwise
    bool update_mac_ttl(const uint8_t* mac, uint8_t new_ttl);

    // Returns true if we changed primary (false->true), false otherwise
    bool make_primary(const uint8_t* mac);

    // Returns true if a new payload entry added, false otherwise
    bool add_payload(HostApplication&, Port, IpProtocol, const AppId payload,
        const AppId service, size_t max_payloads);

    // Returns the hostmac pointer with the highest TTL
    HostMac* get_max_ttl_hostmac();

    // Returns true and copy of the matching HostMac, false if no match...
    bool get_hostmac(const uint8_t* mac, HostMac& hm);

    const uint8_t* get_last_seen_mac();

    void update_vlan(uint16_t vth_pri_cfi_vlan, uint16_t vth_proto);
    bool has_vlan();
    uint16_t get_vlan();
    void get_vlan_details(uint8_t& cfi, uint8_t& priority, uint16_t& vid);

    // The caller owns and deletes the copied list of mac addresses
    void copy_data(uint8_t& p_hops, uint32_t& p_last_seen, std::list<HostMac>*& p_macs);

    bool add_network_proto(const uint16_t type);
    bool add_xport_proto(const uint8_t type);

    // Appid may not be identified always. Inferred means dynamic/runtime
    // appid detected from one flow to another flow such as BitTorrent.
    bool add_service(Port, IpProtocol,
        AppId appid = APP_ID_NONE, bool inferred_appid = false, bool* added = nullptr);
    bool add_service(HostApplication&, bool* added = nullptr);
    void clear_service(HostApplication&);
    void update_service_port(HostApplication&, Port);
    void update_service_proto(HostApplication&, IpProtocol);

    AppId get_appid(Port, IpProtocol, bool inferred_only = false,
        bool allow_port_wildcard = false);

    size_t get_service_count();

    HostApplication add_service(Port, IpProtocol, uint32_t, bool&, AppId appid = APP_ID_NONE);

    void update_service(const HostApplication&);
    bool update_service_info(HostApplication&, const char* vendor, const char* version,
        uint16_t max_info);
    bool update_service_user(Port, IpProtocol, const char* username);
    void remove_inferred_services();

    size_t get_client_count();
    HostClient get_client(AppId id, const char* version, AppId service, bool& is_new);
    bool add_tcp_fingerprint(uint32_t fpid);
    bool add_ua_fingerprint(uint32_t fpid, uint32_t fp_type, bool jail_broken,
        const char* device_info, uint8_t max_devices);

    //  This should be updated whenever HostTracker data members are changed
    void stringify(std::string& str);

    uint8_t get_ip_ttl() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return ip_ttl;
    }

    void set_ip_ttl(uint8_t ttl)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        ip_ttl = ttl;
    }

    uint32_t get_nat_count_start() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return nat_count_start;
    }

    void set_nat_count_start(uint32_t natCountStart)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        nat_count_start = natCountStart;
    }

    uint32_t get_nat_count() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return nat_count;
    }

    void set_nat_count(uint32_t v = 0)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        nat_count = v;
    }

    uint32_t inc_nat_count()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return ++nat_count;
    }

private:
    mutable std::mutex host_tracker_lock; // ensure that updates to a shared object are safe
    uint8_t hops;                 // hops from the snort inspector, e.g., zero for ARP
    uint32_t last_seen;           // the last time this host was seen
    uint32_t last_event;          // the last time an event was generated
    std::list<HostMac, HostMacAllocator> macs; // list guarantees iterator validity on insertion
    std::vector<uint16_t, HostCacheAllocIp<uint16_t>> network_protos;
    std::vector<uint8_t, HostCacheAllocIp<uint8_t>> xport_protos;
    std::vector<HostApplication, HostAppAllocator> services;
    std::vector<HostClient, HostClientAllocator> clients;
    std::set<uint32_t, std::less<uint32_t>, HostCacheAllocIp<uint32_t>> tcp_fpids;
    std::vector<DeviceFingerprint, HostDeviceFpAllocator> ua_fps;

    bool vlan_tag_present = false;
    vlan::VlanTagHdr vlan_tag;
    HostType host_type = HOST_TYPE_HOST;
    uint8_t ip_ttl = 0;
    uint32_t nat_count = 0;
    uint32_t nat_count_start;     // the time nat counting start for this host

    // Hide / delete the constructor from the outside world. We don't want to
    // have zombie host trackers, i.e. host tracker objects that live outside
    // the host cache.
    HostTracker( const HostTracker& ) = delete;
    HostTracker( const HostTracker&& ) = delete;

    HostTracker& operator=( const HostTracker& ) = delete;
    HostTracker& operator=( const HostTracker&& ) = delete;

    // Only the host cache can create them ...
    template<class Key, class Value, class Hash>
    friend class LruCacheShared;

    // These two do not lock independently; they are used by payload discovery and called
    // from add_payload(HostApplication&, Port, IpProtocol, AppId, AppId, size_t); where the
    // lock is actually obtained
    bool add_payload_no_lock(const AppId, HostApplication*);
    HostApplication* find_service_no_lock(Port, IpProtocol, AppId);

    // ... and some unit tests. See Utest.h and UtestMacros.h in cpputest.
    friend class TEST_host_tracker_add_find_service_test_Test;
    friend class TEST_host_tracker_stringify_Test;
};
} // namespace snort
#endif

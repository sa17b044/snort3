//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// rna_logger.h author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_logger.h"

#include <cassert>

#include "managers/event_manager.h"
#include "protocols/packet.h"

#include "rna_fingerprint.h"
#include "rna_logger_common.h"
#include "rna_module.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

// FIXIT-M workaround for OS X, logger should be using sfip anyway
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

using namespace snort;

#ifdef DEBUG_MSGS
static inline void rna_logger_message(const RnaLoggerEvent& rle)
{
    char macbuf[19];
    snprintf(macbuf, 19, "%02X:%02X:%02X:%02X:%02X:%02X",
        rle.mac[0], rle.mac[1], rle.mac[2], rle.mac[3], rle.mac[4], rle.mac[5]);
    if ( rle.ip )
    {
        SfIp ip;
        SfIpString ipbuf;
        ip.set(rle.ip); // using this instead of packet's ip to support ARP
        debug_logf(rna_trace, nullptr, "RNA log: type %u, subtype %u, mac %s, ip %s\n",
            rle.type, rle.subtype, macbuf, ip.ntop(ipbuf));
        if ( rle.hc )
        {
            if ( rle.hc->version[0] != '\0' )
                debug_logf(rna_trace, nullptr,
                    "RNA client log: client %u, service %u, version %s\n",
                    rle.hc->id, rle.hc->service, rle.hc->version);
            else
                debug_logf(rna_trace, nullptr, "RNA client log: client %u, service %u\n",
                    rle.hc->id, rle.hc->service);
        }
        if ( rle.ha )
        {
            debug_logf(rna_trace, nullptr,
                "RNA Service Info log: appid: %d proto %u, port: %u\n",
                rle.ha->appid, (uint32_t)rle.ha->proto, rle.ha->port);

            for ( auto& s: rle.ha->info )
            {
                if ( s.vendor[0] != '\0' )
                    debug_logf(rna_trace, nullptr, "RNA Service Info log: vendor: %s\n",
                        s.vendor);

                if ( s.version[0] != '\0' )
                    debug_logf(rna_trace, nullptr, "RNA Service Info log: version: %s\n",
                        s.version);
            }
        }

        if ( rle.user )
        {
            if ( rle.user and *rle.user )
                debug_logf(rna_trace, nullptr,
                    "RNA user login: service %u, user name %s\n", rle.appid, rle.user);
        }
    }
    else
        debug_logf(rna_trace, nullptr, "RNA log: type %u, subtype %u, mac %s\n",
            rle.type, rle.subtype, macbuf);
}
#endif

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
   const struct in6_addr* src_ip, const uint8_t* src_mac, const HostApplication* ha)
{
    log(type, subtype, src_ip, src_mac, ht, p, 0, 0,
        nullptr, ha);
}

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
   const struct in6_addr* src_ip, const uint8_t* src_mac, const char* user, AppId appid,
   uint32_t event_time)
{
    log(type, subtype, src_ip, src_mac, ht, p, event_time, 0,
        nullptr, nullptr, nullptr, nullptr, nullptr, user, appid);
}

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
       const struct in6_addr* src_ip, const uint8_t* src_mac, const HostClient* hc)
{
    log(type, subtype, src_ip, src_mac, ht, p, 0, 0,
        nullptr, nullptr, nullptr, nullptr, hc);
}

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
    const struct in6_addr* src_ip, const uint8_t* src_mac, const FpFingerprint* fp,
    uint32_t event_time)
{
    log(type, subtype, src_ip, src_mac, ht, p, event_time, 0,
        nullptr, nullptr, fp);
}

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
    const struct in6_addr* src_ip, const uint8_t* src_mac, uint32_t event_time)
{
    log(type, subtype, src_ip, src_mac, ht, p, event_time);
}

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
    const struct in6_addr* src_ip, const uint8_t* src_mac, const HostMac* hm, uint32_t event_time)
{
    log(type, subtype, src_ip, src_mac, ht, p, event_time, 0, hm);
}

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
    uint16_t proto, const uint8_t* src_mac, const struct in6_addr* src_ip, uint32_t event_time)
{
    log(type, subtype, src_ip, src_mac, ht, p, event_time, proto);
}

void RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, const uint8_t* src_mac,
    const struct in6_addr* src_ip, RnaTracker* ht, uint32_t event_time, void* cond_var)
{
    log(type, subtype, src_ip, src_mac, ht, p, event_time, 0,
        nullptr, nullptr, nullptr, cond_var);
}

bool RnaLogger::log(uint16_t type, uint16_t subtype, const struct in6_addr* src_ip,
    const uint8_t* src_mac, RnaTracker* ht, const Packet* p, uint32_t event_time,
    uint16_t proto, const HostMac* hm, const HostApplication* ha,
    const FpFingerprint* fp, void* cond_var, const HostClient* hc,
    const char* user, AppId appid)
{
    if ( !enabled )
        return false;

    assert(ht);

    RnaLoggerEvent rle(type, subtype, src_mac, ht, hm, proto, cond_var, ha, fp, hc, user, appid);
    if ( src_ip and (!IN6_IS_ADDR_V4MAPPED(src_ip) or src_ip->s6_addr32[3]) )
        rle.ip = src_ip;
    else
        rle.ip = nullptr;

    if ( event_time )
    {
        rle.event_time = event_time;
        (*ht)->update_last_event(event_time);
    }

    EventManager::call_loggers(nullptr, const_cast<Packet*>(p), "RNA", &rle);

#ifdef DEBUG_MSGS
    rna_logger_message(rle);
#endif
    return true;
}

#ifdef UNIT_TEST
TEST_CASE("RNA logger", "[rna_logger]")
{
    SECTION("Checking enabled flag")
    {
        RnaTracker ht;
        uint8_t mac[6] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6};
        RnaLogger logger1(false);
        CHECK(logger1.log(0, 0, nullptr, mac, &ht, nullptr, 0, 0,
            nullptr, nullptr, nullptr, nullptr, nullptr) == false);

        RnaLogger logger2(true);
        CHECK(logger2.log(0, 0, nullptr, mac, &ht, nullptr, 0, 0,
            nullptr, nullptr, nullptr, nullptr, nullptr) == true);
    }
}
#endif

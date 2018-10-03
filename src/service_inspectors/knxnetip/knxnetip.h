//--------------------------------------------------------------------------
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
// knxnetip.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_H
#define KNXNETIP_H

#include <cstdint>
#include "framework/counts.h"
#include "protocols/packet.h"

#include "knxnetip_module.h"

struct KNXnetIPStats
{
    PegCount frames;
    PegCount valid_frames;
    PegCount illegal_services;
    PegCount individual_address;
    PegCount illegal_app_services;
    PegCount illegal_group_address;
    PegCount illegal_ia;
    PegCount extremas;
};

class KNXnetIP : public snort::Inspector
{
public:
    KNXnetIP(knxnetip::module::param *p);
    ~KNXnetIP();

    // bool configure(snort::SnortConfig *) override;
    // void show(snort::SnortConfig *) override;

    bool likes(snort::Packet *p) override;
    void eval(snort::Packet* p) override;
    // void clear(snort::Packet* p) override;

    // void meta(int, const uint8_t *) override;

    // int get_message_type(int version, const char* name);
    // int get_info_type(int version, const char* name);

private:
    knxnetip::module::param* params;
};

extern THREAD_LOCAL KNXnetIPStats knxnetip_stats;
#endif // KNXNETIP_H

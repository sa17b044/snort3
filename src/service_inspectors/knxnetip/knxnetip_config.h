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
// knxnetip_module.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_SETTINGS_H
#define KNXNETIP_SETTINGS_H

#include <vector>
#include "sfip/sf_cidr.h"
#include "sfip/sf_ip.h"
#include "protocols/packet.h"

namespace knxnetip {
    namespace module {

        struct Spec
        {
            uint32_t dpt;

            double max;
            double min;
            double frequency;
            double duration;
        };

        struct policy {
            bool individual_addressing = false;
            bool inspection = true;
            bool payload = false;
            bool group_addressing = false;
            int group_address_level = 3;
            std::string group_address_file;
            std::vector<std::string> services;

            // deduced
            std::map<uint16_t,Spec> group_addresses;
            bool load_group_addr(void);
        };

        struct server {
            snort::SfCidr cidr;
            std::vector<int> ports;
            int policy;
        };

        struct param {
            int global_policy;
            std::vector<policy> policies;
            std::vector<server> servers;

        };

        bool validate(param& param);
        bool load(param& param);
        const policy& get_policy(const param* param, const snort::Packet *p);
        bool has_policy(const param* param, const snort::Packet *p);
    }
}

#endif /* KNXNETIP_SETTINGS_H */

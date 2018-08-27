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
#include "log/text_log.h"
//#include "knxnetip_util.h"

#define S_NAME "log_knxnetip"
#define F_NAME S_NAME ".txt"

namespace knxnetip {
    namespace module {

        struct Spec
        {
            uint32_t status;
            uint32_t dpt;

            double max;
            double min;
            double frequency;
            double duration;


            enum class State : uint8_t {
                DPT = 0,
                MAX = 1,
                MIN = 2,
                FREQUENCY = 3,
                DURATION = 4,
                END = 31
            };

            void set_state(State s) { status |= (1 << static_cast<uint8_t>(s)); }
            bool get_state(State s) { return ((1<<static_cast<uint8_t>(s)) & status) == (1<<static_cast<uint8_t>(s)); }
        };

        struct policy {
            bool individual_addressing;
            bool inspection;
            bool header;
            bool payload;
            bool detection;
            int group_address_level;
            std::string group_address_file;
            std::vector<std::string> services;
            std::vector<std::string> app_services;
            std::map<uint16_t,Spec> group_addresses;

            bool load_group_addr(void);
        };

        struct server {
            snort::SfCidr from;
            snort::SfCidr to;
            std::vector<int> ports;
            int policy;
            bool log_knxnetip;
            TextLog* log;
            bool log_to_file;

        };

        struct param {
            int global_policy;
            std::vector<policy> policies;
            std::vector<server> servers;

        };

        bool validate(param& param);
        bool load(param& param);

        void open_log(server& s);
        void close_log(server& s);

        server* get_server_src(param* param, const snort::Packet* p);
        server* get_server_dst(param* param, const snort::Packet* p);
        const policy* get_policy_src(const param* param, const snort::Packet* p);
        const policy* get_policy_dst(const param* param, const snort::Packet* p);
    }
}

#endif /* KNXNETIP_SETTINGS_H */

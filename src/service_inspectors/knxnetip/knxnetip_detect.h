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
// knxnetip_detect.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_DETECT_H
#define KNXNETIP_DETECT_H

#include "knxnetip_config.h"
#include "knxnetip_packet.h"

namespace snort
{
struct Packet;
}

namespace knxnetip {

    void queue_event(const knxnetip::module::policy& policy, unsigned sid);
    void queue_event(unsigned sid);

    namespace detection {
        enum class Comp : uint8_t
        {
            lower = 0x00,
            higher = 0x01
        };

        void detect(knxnetip::Packet& p, const knxnetip::module::policy& policy);
        bool is_individual_address(knxnetip::Packet& p);
        bool is_invalid_group_address(knxnetip::Packet& p, const knxnetip::module::policy& policy);
        bool out_of_bound(knxnetip::Packet& p, const knxnetip::module::policy& policy, Comp comp);
    }

}
#endif /* KNXNETIP_DETECT_H */

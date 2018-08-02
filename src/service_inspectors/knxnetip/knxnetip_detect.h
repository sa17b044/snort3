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
// knxnetip_decode.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_DETECT_H
#define KNXNETIP_DETECT_H

#include "knxnetip_config.h"
#include "knxnetip_packet.h"

namespace snort
{
struct Packet;
}

namespace knxnetip {

namespace packet {
void detect(knxnetip::Packet& p, const knxnetip::module::policy* policy);
}

}
#endif /* KNXNETIP_DETECT_H */

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
// knxnetip_dpt.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_DPT_H
#define KNXNETIP_DPT_H

#include "knxnetip_apdu.h"

namespace knxnetip
{

    namespace dpt
    {
        bool is_dpt_higher(knxnetip::packet::cemi::apdu::GroupValue& gv, uint32_t dpt, double max);
        bool is_dpt_lower(knxnetip::packet::cemi::apdu::GroupValue& gv, uint32_t dpt, double min);


    }


}

#endif /* KNXNETIP_DPT_H */

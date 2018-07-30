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
#include "flow/flow.h"
#include "framework/counts.h"

#include "knxnetip_module.h"



// (Per-session) data block containing current state
// of the KNXnetIP preprocessor.
struct KNXnetIPData
{
    uint32_t state;
};

class KNXnetIPFlowData : public snort::FlowData
{
public:
    KNXnetIPFlowData();
    ~KNXnetIPFlowData() override;

    static void init();
    void reset();

    static unsigned inspector_id;
    KNXnetIPData session;

};

//int get_message_type(int version, const char* name);
//int get_info_type(int version, const char* name);
//


#endif // KNXNETIP_H

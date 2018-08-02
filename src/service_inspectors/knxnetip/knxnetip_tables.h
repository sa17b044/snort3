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
// knxnetip_tables.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_TABLES_H
#define KNXNETIP_TABLES_H

//#include "framework/parameter.h"
#include "framework/module.h"

using namespace snort;

namespace knxnetip {

namespace module {

extern const Parameter server_params[];
extern const Parameter policy_params[];
extern const Parameter params[];

extern const RuleMap events[];
extern const PegInfo peg_names[];
extern const RuleMap rules[];

}

}

#define KNXNETIP_DUMMY 1
#define KNXNETIP_DUMMY_STR "knxnetip dummy rule"

#endif /* KNXNETIP_TABLES_H */

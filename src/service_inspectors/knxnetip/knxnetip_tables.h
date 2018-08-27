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

#include "framework/module.h"

namespace knxnetip {

    namespace module {

        extern const snort::Parameter server_params[];
        extern const snort::Parameter policy_params[];
        extern const snort::Parameter params[];

        extern const snort::RuleMap events[];
        extern const PegInfo peg_names[];
        extern const snort::RuleMap rules[];

        const char *get_rule_str(int sid);

    }

}

#define KNXNETIP_ALERT_START "[**] [%u:%u:%u] \"(knxnetip) "
#define KNXNETIP_ALERT_END "\" [**]\n"
#define KNXNETIP_ALERT_CON_EM "\e[91m"
#define KNXNETIP_ALERT_CON_EM_RESET "\e[0m"

/* Protocol Header */
#define KNXNETIP_HEAD_SIZE 1
#define KNXNETIP_PROT_VERS 2
#define KNXNETIP_TOTAL_LEN 3
#define KNXNETIP_SRVC_TYPE 4

#define KNXNETIP_HEAD_SIZE_STR "invalid header size"
#define KNXNETIP_PROT_VERS_STR "invalid protocol version"
#define KNXNETIP_TOTAL_LEN_STR "total length of packet does not match received length"
#define KNXNETIP_SRVC_TYPE_STR "invalid service type"

/* Protocol Services */
#define KNXNETIP_INDIV_ADDR 11
#define KNXNETIP_INVALID_GROUP_ADDR 12
#define KNXNETIP_SRVC 13
#define KNXNETIP_APP_SRVC 14

#define KNXNETIP_INDIV_ADDR_STR "individual addressing"
#define KNXNETIP_INDIV_ADDR_STR_PAR "individual addressing: <em>(%u.%u.%u)</em>"
#define KNXNETIP_INVALID_GROUP_ADDR_STR "illegal group address"
#define KNXNETIP_INVALID_GROUP_ADDR_STR_PAR "illegal group address: <em>(%u/%u/%u)</em> or <em>(%u/%u)</em>"
#define KNXNETIP_SRVC_STR "illegal service type"
#define KNXNETIP_SRVC_STR_PAR "illegal service type: <em>%s</em>"
#define KNXNETIP_APP_SRVC_STR "illegal application layer service type"
#define KNXNETIP_APP_SRVC_STR_PAR "illegal application layer service type: <em>%s</em>"

/* Group Address */
#define KNXNETIP_GRPADDR_MAX 21
#define KNXNETIP_GRPADDR_MIN 22

#define KNXNETIP_GRPADDR_MAX_STR "value out of range (max)"
#define KNXNETIP_GRPADDR_MAX_STR_PAR "value out of range (max): <em>%s %s</em> (Maximum: <em>%s %s</em>)"
#define KNXNETIP_GRPADDR_MIN_STR "value out of range (min)"
#define KNXNETIP_GRPADDR_MIN_STR_PAR "value out of range (min): <em>%s %s</em> (Minimum: <em>%s %s</em>)"

#define KNXNETIP_DUMMY 100
#define KNXNETIP_DUMMY_STR "knxnetip dummy rule"

#endif /* KNXNETIP_TABLES_H */

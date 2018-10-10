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
//#define KNXNETIP_ALERT_CON_EM ""
//#define KNXNETIP_ALERT_CON_EM_RESET ""

/* Protocol Processing */
#define KNXNETIP_PACKET_PROCESS 1 // inspection
#define KNXNETIP_HEAD_SIZE 2 // inspection
#define KNXNETIP_PROT_VERS 3 // inspection
#define KNXNETIP_TOTAL_LEN 4 // inspection
#define KNXNETIP_SRVC_TYPE 5 // inspection
#define KNXNETIP_EXPECTED_LEN 6 // inspection
#define KNXNETIP_DIB_UNSUPPORTED 7 // inspection
#define KNXNETIP_CONN_TYPE_UNSUPPORTED 8 // inspection
#define KNXNETIP_SELECTOR_UNSUPPORTED 9 // inspection
#define KNXNETIP_APP_SRVC_UNSUPPORTED 10 // inspection
#define KNXNETIP_RESERVED_FIELD_W_DATA 11 // inspection
#define KNXNETIP_CEMI_SRVC_UNSUPPORTED 12 // inspection
#define KNXNETIP_CEMI_PROCESSING_ERROR 13 // inspection

#define KNXNETIP_PKT_PROCESS_STR "erroneous packet content"
#define KNXNETIP_PKT_PROCESS_STR_PAR "erroneous packet content: <em>%u<em> bytes to read, but only <em>%u<em> available"
#define KNXNETIP_HEAD_SIZE_STR "invalid header size"
#define KNXNETIP_PROT_VERS_STR "invalid protocol version"
#define KNXNETIP_TOTAL_LEN_STR "total length of packet does not match received length"
#define KNXNETIP_SRVC_TYPE_STR "invalid service type"
#define KNXNETIP_EXPECTED_LEN_STR "total length of packet does not match expected length"
#define KNXNETIP_DIB_UNSUPPORTED_STR "unsupported DIB type"
#define KNXNETIP_CONN_TYPE_UNSUPPORTED_STR "unsupported connection type"
#define KNXNETIP_SELECTOR_UNSUPPORTED_STR "unsupported SELECTOR type"
#define KNXNETIP_APP_SRVC_UNSUPPORTED_STR "unsupported application layer service type"
#define KNXNETIP_APP_SRVC_UNSUPPORTED_STR_PAR "unsupported application layer service type: <em>%s</em>"
#define KNXNETIP_RESERVED_FIELD_W_DATA_STR "reserved protocol field with data"
#define KNXNETIP_RESERVED_FIELD_W_DATA_STR_PAR "reserved protocol field with data: <em>%s<em>"
#define KNXNETIP_CEMI_SRVC_UNSUPPORTED_STR "unsupported CEMI service"
#define KNXNETIP_CEMI_SRVC_UNSUPPORTED_STR_PAR "unsupported CEMI service: <em>%s<em>"
#define KNXNETIP_CEMI_PROCESSING_ERROR_STR "CEMI processing error"
#define KNXNETIP_CEMI_PROCESSING_ERROR_STR_PAR "CEMI processing error: <em>%s<em>"

/* Anomaly Detection */
#define KNXNETIP_INDIV_ADDR 14 // individual_addressing
#define KNXNETIP_SRVC 15 // detection
#define KNXNETIP_APP_SRVC 16 // detection
#define KNXNETIP_INVALID_GROUP_ADDR 17 // detection
#define KNXNETIP_INVALID_INDIV_ADDR 18 // detection
#define KNXNETIP_GRPADDR_MAX 19 // detection
#define KNXNETIP_GRPADDR_MIN 20 // detection

#define KNXNETIP_INDIV_ADDR_STR "individual addressing"
#define KNXNETIP_INDIV_ADDR_STR_PAR "individual addressing: <em>(%u.%u.%u)</em>"
#define KNXNETIP_SRVC_STR "illegal service type"
#define KNXNETIP_SRVC_STR_PAR "illegal service type: <em>%s</em>"
#define KNXNETIP_APP_SRVC_STR "illegal application layer service type"
#define KNXNETIP_APP_SRVC_STR_PAR "illegal application layer service type: <em>%s</em>"
#define KNXNETIP_INVALID_GROUP_ADDR_STR "illegal group address"
#define KNXNETIP_INVALID_GROUP_ADDR_STR_PAR "illegal group address: <em>%u/%u/%u</em> or <em>%u/%u</em>"
#define KNXNETIP_INVALID_INDIV_ADDR_STR "illegal individual address"
#define KNXNETIP_INVALID_INDIV_ADDR_STR_PAR "illegal individual address <em>%u.%u.%u</em> (<em>%s</em>: group %u/%u/%u or %u/%u, members: %s)"
#define KNXNETIP_GRPADDR_MAX_STR "value out of range (max)"
#define KNXNETIP_GRPADDR_MAX_STR_PAR "value out of range (max): <em>%s %s</em> (Maximum: <em>%s %s</em>)"
#define KNXNETIP_GRPADDR_MIN_STR "value out of range (min)"
#define KNXNETIP_GRPADDR_MIN_STR_PAR "value out of range (min): <em>%s %s</em> (Minimum: <em>%s %s</em>)"

//#define KNXNETIP_DUMMY 100
//#define KNXNETIP_DUMMY_STR "knxnetip dummy rule"

#endif /* KNXNETIP_TABLES_H */

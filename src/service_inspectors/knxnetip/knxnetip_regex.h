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
// knxnetip_regex.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_REGEX_H
#define KNXNETIP_REGEX_H

#define KNXNETIP_CIDR_N             "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
#define KNXNETIP_CIDR_S             "([0-9]|[1-2][0-9]|3[0-2])"
#define KNXNETIP_CIDR_REGEX         "^" \
                                    KNXNETIP_CIDR_N "\\." KNXNETIP_CIDR_N "\\." \
                                    KNXNETIP_CIDR_N "\\." KNXNETIP_CIDR_N "\\/" \
                                    KNXNETIP_CIDR_S "$"

#define KNXNETIP_GRP_ADDR_DELIM     "\\/"
#define KNXNETIP_GRP_ADDR_S         "(^|\\.|\\ )"
#define KNXNETIP_GRP_ADDR_E         "(\\ |\\t|$)+"
#define KNXNETIP_GRP_ADDR_MAIN      "([0-9]|1[0-5])"
#define KNXNETIP_GRP_ADDR_MID       "([0-7])"

#define KNXNETIP_GRP_ADDR_3_SUB     "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
#define KNXNETIP_GRP_ADDR_3_REGEX   KNXNETIP_GRP_ADDR_S     "(" \
                                    KNXNETIP_GRP_ADDR_MAIN KNXNETIP_GRP_ADDR_DELIM \
                                    KNXNETIP_GRP_ADDR_MID  KNXNETIP_GRP_ADDR_DELIM \
                                    KNXNETIP_GRP_ADDR_3_SUB ")" \
                                    KNXNETIP_GRP_ADDR_E

#define KNXNETIP_GRP_ADDR_2_SUB     "([0-9]|[1-9][0-9]|[1-9][0-9][0-9]|1[0-9][0-9][0-9]|20[0-3][0-9]|204[0-7])"
#define KNXNETIP_GRP_ADDR_2_REGEX   KNXNETIP_GRP_ADDR_S     "(" \
                                    KNXNETIP_GRP_ADDR_MAIN KNXNETIP_GRP_ADDR_DELIM \
                                    KNXNETIP_GRP_ADDR_2_SUB ")" \
                                    KNXNETIP_GRP_ADDR_E

#endif /* KNXNETIP_REGEX_H */

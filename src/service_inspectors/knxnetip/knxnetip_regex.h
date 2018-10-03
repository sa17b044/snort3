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


namespace knxnetip
{
    namespace regex {

        namespace xml {
            constexpr static auto valid_xml_line {R"###(<[^!--].*?\/?>)###"};
            constexpr static auto valid_line {R"###(<GroupAddress .*?\/?>)###"};
            constexpr static auto valid_address {R"###(Address="(.*?)")###"};
            constexpr static auto valid_dpt {R"###(DPTs="(.*?)")###"};
            constexpr static auto valid_descr {R"###(Name="(.*?)")###"};
        }

        namespace csv {
            constexpr static auto valid_group_address {R"###("(\d+\/\d+\/\d+)")###"};
            constexpr static auto valid_dpt {R"###("(DPS?T-\d+(-\d+)?)")###"};
        }

        constexpr static auto group_address_3l {R"###((\d+)\/(\d+)\/(\d+))###"};
        constexpr static auto group_address_2l {R"###((\d+)\/(\d+))###"};
        constexpr static auto data_point_type {R"###(DPS?T-(\d+)(?:-(\d+))?)###"};

        constexpr static auto cidr {R"###((\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+))###"};
        constexpr static auto file_ext {R"###(\.([[:alpha:]]+)$)###"};


        constexpr static auto valid_dpt_max {R"###(max[:=]"([+-]?\d+(?:.\d+)?)")###"};
        constexpr static auto valid_dpt_min {R"###(min[:=]"([+-]?\d+(?:.\d+)?)")###"};

        constexpr static auto valid_individual_address {R"###(ia[:=]"(.*?)")###"};
        constexpr static auto individual_address {R"###((\d+).(\d+).(\d+))###"};
    }
}

#endif /* KNXNETIP_REGEX_H */

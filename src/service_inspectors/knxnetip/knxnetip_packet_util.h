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
// knxnetip_packet_util.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_PACKET_UTIL_H
#define KNXNETIP_PACKET_UTIL_H

#include <arpa/inet.h>
#include <cstdint>
#include <string>
#include "protocols/packet.h"
//#include "detection/detection_engine.h"
#include "knxnetip_util.h"
#include "knxnetip_module.h"
#include "knxnetip_tables.h"

namespace knxnetip
{
    namespace packet
    {
        /* Host Protocol Address Information */
        class HPAI {
            const uint8_t* structure_length;
            const uint8_t* host_protocol;
            const uint32_t* ip;
            const uint16_t* port;

        public:
            void load(const snort::Packet& p, int& offset, const knxnetip::module::server& server, const knxnetip::module::policy& policy);

            uint8_t get_structure_length() const { return *structure_length; }
            uint8_t get_host_protocol() const { return *host_protocol; }
            std::string get_ip() const { return std::string{inet_ntoa({(in_addr_t)(*ip)})}; }
            uint16_t get_port() const { return htons(*port); }
        };

        /* Description Information Block */
        namespace dib
        {

            enum class Type : uint8_t {
                DEVICE_INFO = 0x01,
                SUPP_SVC = 0x02,
                IP_CONF = 0x03,
                IP_CURRENT = 0x04,
                KNX_ADDRESS = 0x05,
                MFR_DATA = 0xFE
            };

            enum class MediumCode : uint8_t {
                reserved = 0x01,
                KNX_TP = 0x02,
                KNX_PL110 = 0x03,
                reserved2 = 0x04,
                KNX_RF = 0x10,
                KNX_IP = 0x20
            };

            class DeviceInfo
            {
                const uint8_t* knx_medium;
                const uint8_t* device_status;
                const uint16_t* knx_individual_address;
                const uint16_t* project_inst_id;
                const uint8_t* serial_number; //[6];
                const uint32_t* multicast_address;
                const uint8_t* mac_address; //[6];
                const char* device_friendly_name;//[30];

            public:
                constexpr static const uint8_t ser_num_size = 6;
                constexpr static const uint8_t mac_adr_size = 6;
                constexpr static const uint8_t dev_nam_size = 30;
                void load(const snort::Packet& p, int& offset);

                knxnetip::packet::dib::MediumCode get_knx_medium() const { return static_cast<knxnetip::packet::dib::MediumCode>(*knx_medium); }
                uint8_t get_device_status() const { return *device_status; }
                uint16_t get_knx_individual_address() const { return ntohs(*knx_individual_address); }
                uint16_t get_project_inst_id() const { return ntohs(*project_inst_id); }
                uint8_t get_serial_number(int i) const { return i >= ser_num_size ? 0 : serial_number[i]; }
                uint32_t get_multicast_address() const { return ntohl(*multicast_address); }
                uint8_t get_mac_address(int i) const { return i >= mac_adr_size ? 0 : mac_address[i]; };
                std::string get_device_friendly_name() const { std::string s{device_friendly_name}; return (s.length() > dev_nam_size) ? s.substr(0,dev_nam_size) : s; }
            };

            class SuppSvcFamily
            {
                const uint8_t* id;
                const uint8_t* version;

            public:
                uint8_t size;

                void load(const snort::Packet& p, int& offset, uint8_t dib_structure_length);

                uint8_t get_id(int i) const { return i >= size ? 0 : *(id + (i*2)); }
                uint8_t get_version(int i) const { return i >= size ? 0 : *(version + (i*2)); }
            };

            class IpConfig
            {
                const uint32_t* ip;
                const uint32_t* subnet;
                const uint32_t* gateway;
                const uint8_t* capabilities;
                const uint8_t* assignment_method;

            public:
                void load(const snort::Packet& p, int& offset);

                std::string get_ip() const { return std::string{inet_ntoa({(in_addr_t)(*ip)})}; }
                std::string get_subnet() const { return std::string{inet_ntoa({(in_addr_t)(*subnet)})}; }
                std::string get_gateway() const { return std::string{inet_ntoa({(in_addr_t)(*gateway)})}; }
                uint8_t get_capabilities() const { return *capabilities; }
                uint8_t get_assignment_method() const { return *assignment_method; }
            };

            class IpCurrent
            {
                const uint32_t* ip;
                const uint32_t* subnet;
                const uint32_t* gateway;
                const uint32_t* dhcp;
                const uint8_t* assignment_method;
                const uint8_t* reserved;

            public:
                void load(const snort::Packet& p, int& offset, const knxnetip::module::server& server, const knxnetip::module::policy& policy);
                void load(const snort::Packet& p, int& offset);

                std::string get_ip() const { return std::string{inet_ntoa({(in_addr_t)(*ip)})}; }
                std::string get_subnet() const { return std::string{inet_ntoa({(in_addr_t)(*subnet)})}; }
                std::string get_gateway() const { return std::string{inet_ntoa({(in_addr_t)(*gateway)})}; }
                std::string get_dhcp() const { return std::string{inet_ntoa({(in_addr_t)(*dhcp)})}; }
                uint8_t get_assignment_method() const { return *assignment_method; }
            };

            class KnxAddress
            {
                const uint16_t* address;

            public:
                void load(const snort::Packet& p, int& offset);

                uint16_t get_address() const { return ntohs(*address); }
            };

            class MfrData
            {
                const uint16_t* manufacturer_id;
                const char* manufacturer_data;

            public:
                uint8_t size;
                void load(const snort::Packet& p, int& offset, uint8_t dib_structure_length);

                uint16_t get_manufacturer_id() const { return *manufacturer_id; }
                std::string get_manufacturer_data() const { std::string s{manufacturer_data}; return (s.length() > size) ? s.substr(0, size) : s; }
            };

        }

        class DIB {
            const uint8_t* dib_structure_length;
            const uint8_t* dib_type;

        public:
            union {
                dib::DeviceInfo device_info;
                dib::SuppSvcFamily supp_svc_families;
                dib::IpConfig ip_config;
                dib::IpCurrent ip_current;
                dib::KnxAddress knx_address;
                dib::MfrData mfr_data;
            };

            void load(const snort::Packet& p, int& offset, const knxnetip::module::server& server, const knxnetip::module::policy& policy);
            void load(const snort::Packet& p, int& offset);

            uint8_t get_dib_structure_length() const { return *dib_structure_length; }
            const dib::Type get_dib_type() const { return static_cast<const dib::Type>(*dib_type); }
        };

        /* Connection Request Information/Response Data Block */
        namespace cr
        {
            enum class ConnType : uint8_t {
                DEVICE_MGMT_CONNECTION = 0x03,
                TUNNEL_CONNECTION = 0x04,
                REMLOG_CONNECTION = 0x06,
                REMCONF_CONNECTION = 0x07,
                OBJSVR_CONNECTION = 0x08
            };

            class CR {
                const uint8_t* structure_length;
                const uint8_t* connection_type_code;

            public:
                void load(const snort::Packet& p, int& offset);

                uint8_t get_structure_length() const { return *structure_length; }
                ConnType get_connection_type_code() const { return static_cast<ConnType>(*connection_type_code); }
            };

        };

        class CRI : cr::CR {
            enum class TunnellingKNXLayer : uint8_t {
                TUNNEL_LINKLAYER = 0x02,
                TUNNEL_RAW = 0x04,
                TUNNEL_BUSMONITOR = 0x80
            };

            const uint8_t *knx_layer;
            const uint8_t *reserved;

        public:
            void load(const snort::Packet& p, int& offset, const knxnetip::module::server& server, const knxnetip::module::policy& policy);

            uint8_t get_knx_layer() const { return *knx_layer; }
        };

        class CRD : cr::CR {
            const uint16_t *knx_address;

        public:
            void load(const snort::Packet& p, int& offset, const knxnetip::module::server& server, const knxnetip::module::policy& policy);

            uint16_t get_knx_address() const { return ntohs(*knx_address); }
        };

        /* Connection Header */
        class ConnectionHeader
        {
            const uint8_t* structure_length;
            const uint8_t* communication_channel_id;
            const uint8_t* sequence_counter;
            union {
                const uint8_t* reserved;
                const uint8_t* status;
            };

        public:
            void load(const snort::Packet& p, int& offset);

            uint8_t get_structure_length() const { return *structure_length; }
            uint8_t get_communication_channel_id() const { return *communication_channel_id; }
            uint8_t get_sequence_counter() const { return *sequence_counter; }
            uint8_t get_status() const { return *status; }
        };

        /* Remote Diagnostic and Configuration Selector */
        class SELECTOR
        {
            const uint8_t* structure_length;
            const uint8_t* selector_type_code;
            const uint8_t* mac_address; //[6];

        public:
            constexpr static const uint8_t mac_adr_size = 6;

            enum class Type : uint8_t {
                PrgMode = 0x01,
                MAC = 0x02
            };

            void load(const snort::Packet& p, int& offset);

            uint8_t get_structure_length() const { return *structure_length; }
            SELECTOR::Type get_selector_type_code() const { return static_cast<Type>(*selector_type_code); }
            uint8_t get_mac_address(int i) const { return (get_selector_type_code() != Type::MAC) and (i >= mac_adr_size) ? 0 : mac_address[i]; };
        };

    }
}

#endif /* KNXNETIP_PACKET_UTIL_H */

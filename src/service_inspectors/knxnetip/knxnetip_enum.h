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
// knxnetip_enum.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_ENUM_H
#define KNXNETIP_ENUM_H

#include <cstdint>
#include <map>
#include <string>

#include "knxnetip_packet_util.h"
#include "knxnetip_cemi.h"

namespace knxnetip
{

    /* Common constants */
    constexpr static const uint8_t KNXNETIP_VERSION_10 = 0x10;
    constexpr static const uint8_t KNXNETIP_VERSION_13 = 0x13;
    constexpr static const uint8_t HEADER_SIZE = 0x6;

    enum class ServiceType : uint16_t {
        /* Core Service Type Identifiers */
        SEARCH_REQ = 0x201,
        SEARCH_RES = 0x202,
        DESCRIPTION_REQ = 0x203,
        DESCRIPTION_RES = 0x204,
        CONNECT_REQ = 0x205,
        CONNECT_RES = 0x206,
        CONNECTIONSTATE_REQ = 0x207,
        CONNECTIONSTATE_RES = 0x208,
        DISCONNECT_REQ = 0x209,
        DISCONNECT_RES = 0x20A,
        /* Device Management Service Type Identifiers */
        DEVICE_CONFIGURATION_REQ = 0x310,
        DEVICE_CONFIGURATION_ACK = 0x311,
        /* Tunnelling Service Type Identifiers */
        TUNNELLING_REQ = 0x420,
        TUNNELLING_ACK = 0x421,
        /* Routing Service Type Identifiers */
        ROUTING_INDICATION = 0x530,
        ROUTING_LOST = 0x531,
        ROUTING_BUSY = 0x532,
        /* Remote Diagnosis and Configuration Type Identifiers */
        REMOTE_DIAG_REQ = 0x740,
        REMOTE_DIAG_RES = 0x741,
        REMOTE_BASIC_CONF_REQ = 0x742,
        REMOTE_RESET_REQ = 0x743,
        /* KNXnet/IP Secure */
        SECURE_WRAPPER = 0xaa00,
        SECURE_CHANNEL_REQ = 0xaa01,
        SECURE_CHANNEL_RES = 0xaa02,
        SECURE_CHANNEL_AUTH = 0xaa03,
        SECURE_CHANNEL_STAT = 0xaa04,
        SECURE_GROUP_SYNC_REQ = 0xaa06,
        SECURE_GROUP_SYNC_RES = 0xaa07
    };


#define KNX_GRPADDR_MAIN_MAX            (31)
#define KNX_GRPADDR_MAIN_S              (11)
#define KNX_GRPADDR_MAIN_M              (0xf800)
#define KNX_GRPADDR2_DEV_MAX            (2047)
#define KNX_GRPADDR2_DEV_M              (0x7ff)
#define KNX_GRPADDR_MID_MAX             (7)
#define KNX_GRPADDR_MID_S               (8)
#define KNX_GRPADDR_MID_M               (0x0700)
#define KNX_GRPADDR3_DEV_MAX            (255)
#define KNX_GRPADDR3_DEV_M              (0xff)

#define KNX_IA_AREA_MAX                 (15)
#define KNX_IA_AREA_S                   (12)
#define KNX_IA_AREA_M                   (0xf000)
#define KNX_IA_LINE_MAX                 (15)
#define KNX_IA_LINE_S                   (8)
#define KNX_IA_LINE_M                   (0xf00)
#define KNX_IA_DEVICE_MAX               (255)
#define KNX_IA_DEVICE_M                 (0xff)

#define FLAGS_DEVICESTATUS_RESERVED     (0xFE)
#define FLAGS_DEVICESTATUS_PROGRAM      (0x01)
#define FLAGS_IPCAPABILITES_RESERVED    (0xF8)
#define FLAGS_IPCAPABILITES_BOOTIP      (0x01)
#define FLAGS_IPCAPABILITES_DHCP        (0x02)
#define FLAGS_IPCAPABILITES_AUTOIP      (0x04)
#define FLAGS_DEVICESTATE_RESERVED      (0xFC)
#define FLAGS_DEVICESTATE_KNX           (0x01)
#define FLAGS_DEVICESTATE_IP            (0x02)

/*for CEMI*/
//#define A_GROUPVALUE_RES                (0x040)
//#define A_GROUPVALUE_WRT                (0x080)
//#define A_ADC_RED                       (0x180)
//#define A_ADC_RES                       (0x1C0)
//#define A_MEM_RED                       (0x200)
//#define A_MEM_RES                       (0x240)
//#define A_MEM_WRT                       (0x280)
//#define A_SYS_RED                       (0x1C8)
//#define A_SYS_RES                       (0x1C9)
//#define A_SYS_WRT                       (0x1CA)
//#define A_SYS_BROAD                     (0x1CB)
#define GROUPADD                        (0x80)
#define COUPLER_SPECIFIC_SERVICE        (0x3C0)
//#define A_AUTHORIZE_REQ                 (0x3D1)
//#define A_AUTHORIZE_RES                 (0x3D2)
//#define A_KEY_WRT                       (0x3D3)
//#define A_KEY_RES                       (0x3D4)
//#define A_PROPVALUE_RED                 (0x3D5)
//#define A_PROPVALUE_RES                 (0x3D6)
/* Control field 2 */
#define DAT_INDIVIDUAL 	                 (0x00)
#define DAT_GROUP		                 (0x80)

extern std::map<knxnetip::ServiceType, std::string> service_identifier;
extern std::map<uint8_t, std::string> service_type;
extern std::map<uint8_t, std::string> connection_type;
extern std::map<uint8_t, std::string> connect_response_status_code;
extern std::map<uint8_t, std::string> connectionstate_response_status_code;
extern std::map<uint8_t, std::string> tunneling_error_code;
extern std::map<uint8_t, std::string> device_configuration_ack_status_code;
extern std::map<knxnetip::packet::dib::Type, std::string> dib_description_type_code;
extern std::map<knxnetip::packet::dib::MediumCode, std::string> dib_medium_code;
extern std::map<uint8_t, std::string> host_protocol_code;
extern std::map<uint8_t, std::string> ip_assignment_method;
extern std::map<uint8_t, std::string> knxlayer_value;
extern std::map<uint8_t, std::string> selector_type;
extern std::map<uint8_t, std::string> reset_code;

/*for CEMI*/
extern std::map<knxnetip::packet::cemi::MessageCode, std::string> cemi_messagecode;
extern std::map<knxnetip::packet::cemi::add_info::TypeId, std::string> cemi_add_type_id;
extern std::map<uint8_t, std::string> cemi_tpci_val;
extern std::map<uint16_t, std::string> cemi_apci_code;
extern std::map<knxnetip::packet::cemi::iot::InterfaceObjectType, std::string> cemi_interfacobject;
extern std::map<uint8_t, std::string> cemi_propertyid;
extern std::map<knxnetip::packet::cemi::pid::PropertyIdentifier, std::string> cemi_propertyid_default;
extern std::map<knxnetip::packet::cemi::pid::device::PropertyIdentifier, std::string> cemi_propertyid_default_device;
extern std::map<knxnetip::packet::cemi::pid::polling_master::PropertyIdentifier, std::string> cemi_propertyid_default_polling_master;
extern std::map<knxnetip::packet::cemi::ErrorCode, std::string> cemi_error_code;
extern std::map<uint8_t, std::string> cemi_bibat_ctrl;

}

#endif /* KNXNETIP_ENUM_H */

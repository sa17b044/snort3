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
// knxnetip_apdu.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_APDU_H
#define KNXNETIP_APDU_H

#include <arpa/inet.h>
#include <cstdint>
#include <map>
#include <string>
#include "protocols/packet.h"
#include "knxnetip_config.h"

namespace knxnetip
{
    namespace packet
    {
        /* Common External Message Interface */
        namespace cemi {

            /* Application Protocol Data Unit */
            namespace apdu {

                enum class Type : uint16_t {
                    A_GroupValue_Read = 0x000,
                    A_GroupValue_Response = 0x040,
                    A_GroupValue_Write = 0x080,
                    A_IndividualAddress_Write = 0x0c0,
                    A_IndividualAddress_Read = 0x100,
                    A_IndividualAddress_Response = 0x140,
                    A_ADC_Read = 0x180,
                    A_ADC_Response = 0x1c0,
                    A_SystemNetworkParameter_Read = 0x1c8,
                    A_SystemNetworkParameter_Response = 0x1c9,
                    A_SystemNetworkParameter_Write = 0x1ca,
                    planned = 0x1cb,
                    A_Memory_Read = 0x200,
                    A_Memory_Response = 0x240,
                    A_Memory_Write = 0x280,
                    A_UserMemory_Read = 0x2c0,
                    A_UserMemory_Response = 0x2c1,
                    A_UserMemory_Write = 0x2c2,
                    A_UserMemoryBit_Write = 0x2c4,
                    A_UserManufacturerInfo_Read = 0x2c5,
                    A_UserManufacturerInfo_Response = 0x2c6,
                    A_FunctionPropertyCommand = 0x2c7,
                    A_FunctionPropertyState_Read = 0x2c8,
                    A_FunctionPropertyState_Response = 0x2c9,
                    reserved_UserMsg_S = 0x2ca,
                    reserved_UserMsg_E = 0x2f7,
                    reserved_UserMsg_Manu_S = 0x2f8,
                    reserved_UserMsg_Manu_E = 0x2fe,
                    A_DeviceDescriptor_Read = 0x300,
                    A_DeviceDescriptor_Response = 0x340,
                    A_Restart = 0x380,
                    // A_Restart_Response = 0x381,
                    A_Open_Routing_Table_Req = 0x3c0,
                    A_Read_Routing_Table_Req = 0x3c1,
                    A_Read_Routing_Table_Res = 0x3c2,
                    A_Write_Routing_Table_Req = 0x3c3,
                    A_Read_Router_Memory_Req = 0x3c8,
                    A_Read_Router_Memory_Res = 0x3c9,
                    A_Write_Router_Memory_Req = 0x3ca,
                    A_Read_Router_Status_Req = 0x3cd,
                    A_Read_Router_Status_Res = 0x3ce,
                    A_Write_Router_Status_Req = 0x3cf,
                    A_MemoryBit_Write = 0x3d0,
                    A_Authorize_Request = 0x3d1,
                    A_Authorize_Response = 0x3d2,
                    A_Key_Write = 0x3d3,
                    A_Key_Response = 0x3d4,
                    A_PropertyValue_Read = 0x3d5,
                    A_PropertyValue_Response = 0x3d6,
                    A_PropertyValue_Write = 0x3d7,
                    A_PropertyDescription_Read = 0x3d8,
                    A_PropertyDescription_Response = 0x3d9,
                    A_NetworkParameter_Read = 0x3da,
                    A_NetworkParameter_Response = 0x3db,
                    A_IndividualAddressSerialNumber_Read = 0x3dc,
                    A_IndividualAddressSerialNumber_Respone = 0x3dd,
                    A_IndividualAddressSerialNumber_Write = 0x3de,
                    reserved = 0x3df,
                    A_DomainAddress_Write = 0x3e0,
                    A_DomainAddress_Read = 0x3e1,
                    A_DomainAddress_Response = 0x3e2,
                    A_DomainAddressSelective_Read = 0x3e3,
                    A_NetworkParameter_Write = 0x3e4,
                    A_Link_Read = 0x3e5,
                    A_Link_Response = 0x3e6,
                    A_Link_Write = 0x3e7,
                    A_GroupPropValue_Read = 0x3e8, // unsupported
                    A_GroupPropValue_Response = 0x3e9, // unsupported
                    A_GroupPropValue_Write = 0x3ea, // unsupported
                    A_GroupPropValue_InfoReport = 0x3eb, // unsupported
                    A_DomainAddressSerialNumber_Read = 0x3ec,
                    A_DomainAddressSerialNumber_Response = 0x3ed,
                    A_DomainAddressSerialNumber_Write = 0x3ee,
                    A_FileStream_InfoReport = 0x3f0
                };

                extern std::map<Type, std::string> app_service_identifier;

                class GroupValue
                {
                public:
                    const uint8_t* data;
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint8_t get_data(int i) const { return i < 0 or i > length ? 0 : length == 1 ? (*data) & 0x3f : *(data + i); }
                };

                class IndividualAddress
                {
                    const uint16_t* address;

                public:
                    void load(const snort::Packet& p, int& offset, apdu::Type t);

                    uint16_t get_address() const { return ntohs(*address); }
                };

                class ADC
                {
                    const uint8_t* channel_nr;
                    const uint8_t* read_count;
                    const uint16_t* sum;
                public:
                    void load(const snort::Packet& p, int& offset, apdu::Type t);

                    uint8_t get_channel_nr() const { return (*channel_nr) & 0x3f; }
                    uint8_t get_read_count() const { return *read_count; }
                    uint16_t get_sum() const { return ntohs(*sum); }
                };

                /* FIXME: implement error handling */
                class SystemNetworkParameter
                {
                    const uint16_t* object_type;
                    const uint16_t* property_id;
                    union {
                        const uint8_t* test_info;
                        const uint8_t* value;
                    };
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint16_t get_object_type() const { return ntohs(*object_type); }
                    uint16_t get_property_id() const { return ntohs((*property_id) & 0xfff0) >> 4; }
                    uint8_t get_test_info(int i) const { return i < 0 or i > length ? 0 : *(test_info + i); }
                    uint8_t get_value(int i) const { return i < 0 or i > length ? 0 : *(value + i); }
                };

                class Memory
                {
                    const uint8_t* number;
                    const uint16_t* address;
                    const uint8_t* data;
                public:
                    void load(const snort::Packet& p, int& offset, apdu::Type t);

                    uint8_t get_number() const { return (*number) & 0x3f; }
                    uint16_t get_address() const { return ntohs(*address); }
                    uint8_t get_data(int i) const { return i < 0 or i > get_number() ? 0 : *(data + i); }
                };

                class UserMemory
                {
                    const uint8_t* addr_num;
                    const uint16_t* address;
                    const uint8_t* data;
                public:
                    void load(const snort::Packet& p, int& offset, apdu::Type t);

                    uint8_t get_address_ext() const { return (*addr_num) >> 4; }
                    uint8_t get_number() const { return (*addr_num) & 0xf; }
                    uint16_t get_address() const { return ntohs(*address); }
                    uint8_t get_data(int i) const { return i < 0 or i > get_number() ? 0 : *(data + i); }
                };

                class UserMemoryBit
                {
                    const uint8_t* number;
                    const uint16_t* address;
                    const uint8_t* and_data;
                    const uint8_t* xor_data;
                public:
                    void load(const snort::Packet& p, int& offset);

                    uint8_t get_number() const { return *number; }
                    uint16_t get_address() const { return ntohs(*address); }
                    uint8_t get_and_data(int i) const { return i < 0 or i > get_number() ? 0 : *(and_data + i); }
                    uint8_t get_xor_data(int i) const { return i < 0 or i > get_number() ? 0 : *(xor_data + i); }
                };

                class UserManufacturerInfo
                {
                    const uint8_t* manufacturer_id;
                    const uint8_t* manufacturer_specific; //[2]
                public:
                    constexpr static const uint8_t man_spec_size = 2;
                    void load(const snort::Packet& p, int& offset, apdu::Type t);

                    uint8_t get_manufacturer_id() const { return *manufacturer_id; }
                    uint8_t get_manufacturer_data(int i) const { return i < 0 or i > man_spec_size ? 0 : *(manufacturer_specific + i); }
                };

                class FunctionPropertyCommand
                {
                    const uint8_t* object_index;
                    const uint8_t* property_id;
                    const uint8_t* data;
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, uint8_t information_length);

                    uint8_t get_object_index() const { return *object_index; }
                    uint8_t get_property_id() const { return *property_id; }
                    uint8_t get_data(int i) const { return i < 0 or i > length ? 0 : *(data +i ); }
                };

                /* FIXME: implement error handling */
                class FunctionPropertyState
                {
                    const uint8_t* object_index;
                    const uint8_t* property_id;
                    const uint8_t* return_code;
                    const uint8_t* data;
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint8_t get_object_index() const { return *object_index; }
                    uint8_t get_property_id() const { return *property_id; }
                    uint8_t get_return_code() const { return *return_code; }
                    uint8_t get_data(int i) const { return i < 0 or i > length ? 0 : *(data +i ); }
                };

                class DeviceDescriptor
                {
                    const uint8_t* descriptor_type;
                    const uint8_t* device_descriptor;
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, apdu::Type, uint8_t information_length);

                    uint8_t get_descriptor_type() const { return (*descriptor_type) & 0x3f; }
                    uint8_t get_device_descriptor(int i) const { return i < 0 or i > length ? 0 : *(device_descriptor + i); }
                };

                /* FIXME: implement error handling */
                class Restart
                {
                    const uint8_t* data;
                    union {
                        const uint8_t* erase_code;
                        const uint8_t* error_code;
                    };
                    union {
                        const uint8_t* channel_nr;
                        const uint16_t* process_time;
                    };
                public:
                    void load(const snort::Packet& p, int& offset);

                    bool is_master_reset() const { return ((*data) & 0x1) == 0x1; }
                    bool is_response() const { return ((*data) & 0x20) == 0x20; }
                    uint8_t get_erase_code() const { return *erase_code; }
                    uint8_t get_error_code() const { return *error_code; }
                    uint8_t get_channel_nr() const { return *channel_nr; }
                    uint16_t get_process_time() const { return *process_time; }
                };

                class MemoryBit
                {
                    const uint8_t* number;
                    const uint16_t* address;
                    const uint8_t* and_data;
                    const uint8_t* xor_data;
                public:
                    void load(const snort::Packet& p, int& offset);

                    uint8_t get_number() const { return *number; }
                    uint16_t get_address() const { return ntohs(*address); }
                    uint8_t get_and_data(int i) const { return i < 0 or i > get_number() ? 0 : *(and_data + i); }
                    uint8_t get_xor_data(int i) const { return i < 0 or i > get_number() ? 0 : *(xor_data + i); }
                };

                /* FIXME: implement error handling */
                class Authorize
                {
                    union {
                        const uint8_t* reserved;
                        const uint8_t* level;
                    };
                    const uint32_t* key;
                public:
                    void load(const snort::Packet& p, int& offset, apdu::Type t, const knxnetip::module::server& server, const knxnetip::module::policy& policy);

                    uint8_t get_level() const { return *level; }
                    uint32_t get_key() const { return ntohl(*key); }
                };

                class Key
                {
                    const uint8_t* level;
                    const uint32_t* key;
                public:
                    void load(const snort::Packet& p, int& offset, apdu::Type t);

                    uint8_t get_level() const { return *level; }
                    uint32_t get_key() const { return ntohl(*key); }
                };

                /* FIXME: implement error handling */
                class PropertyValue
                {
                    const uint8_t* object_index;
                    const uint8_t* property_id;
                    const uint16_t* elem_six;
                    const uint8_t* data;
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint8_t get_object_index() const { return *object_index; }
                    uint8_t get_property_id() const { return *property_id; }
                    uint8_t get_number_of_elements() const { return static_cast<uint8_t>((*elem_six) >> 12); }
                    uint16_t get_start_index() const { return ntohs((*elem_six) & 0xfff); }
                    uint8_t get_data(int i) const { return i < 0 or i > length ? 0 : *(data + i); }
                };

                class PropertyDescription
                {
                    const uint8_t* object_index;
                    const uint8_t* property_id;
                    const uint8_t* property_index;
                    const uint8_t* type;
                    const uint16_t* max_elem;
                    const uint8_t* access;
                public:
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint8_t get_object_index() const { return *object_index; }
                    uint8_t get_property_id() const { return *property_id; }
                    uint8_t get_property_index() const { return *property_index; }
                    bool is_writeable() const { return ((*type) & 0x80) == 0x80; }
                    uint8_t get_type() const { return (*type) & 0x3f; }
                    uint16_t get_max_number_of_elements() const { return ntohs((*max_elem) & 0x3ff); }
                    uint8_t get_read_access_level() const { return (*access) >> 4; }
                    uint8_t get_write_access_level() const { return (*access) & 0xf; }
                };

                /* FIXME: implement error handling */
                class NetworkParameter
                {
                    const uint16_t* object_type;
                    const uint8_t* property_id;
                    union {
                        const uint8_t* test_info;
                        const uint8_t* value;
                    };
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, uint8_t information_length);

                    uint16_t get_object_type() const { return ntohs(*object_type); }
                    uint8_t get_property_id() const { return *property_id; }
                    uint8_t get_test_info(int i) const { return i < 0 or i > length ? 0 : *(test_info + i); }
                    uint8_t get_value(int i) const { return i < 0 or i > length ? 0 : *(value + i); }
                };

                class IndividualAddressSerialNumber
                {
                    const uint8_t* serial_number; //[6];
                    const uint16_t* domain_address;
                    union {
                        const uint16_t* reserved;
                        const uint32_t* reserved2;
                    };
                public:
                    constexpr static const uint8_t ser_num_size = 6;

                    void load(const snort::Packet& p, int& offset, apdu::Type t, const knxnetip::module::server& server, const knxnetip::module::policy& policy);

                    uint8_t get_serial_number(int i) const { return i >= ser_num_size ? 0 : serial_number[i]; }
                    uint16_t get_domain_address() const { return *domain_address; }
                };

                class DomainAddress
                {
                    const uint8_t* domain_address;
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint8_t get_domain_address(int i) const { return i < 0 or i > length ? 0 : *(domain_address + i); }
                };

                /* FIXME: implement error handling */
                class Link
                {
                    const uint8_t* group_object_number;
                    union {
                        const uint8_t* addr_six;
                        const uint8_t* flags;
                    };
                    const uint16_t* group_address_list;
                    uint8_t length;
                public:
                    uint8_t num_group_addresses;
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint8_t get_group_object_number() const { return *group_object_number; }
                    uint8_t get_sending_address() const { return (*addr_six) >> 4; }
                    uint8_t get_start_address() const { return (*addr_six) & 0xf; }
                    bool is_deletion() const { return ((*flags) & 0x2) == 0x2; }
                    bool is_sending() const { return ((*flags) & 0x1) == 0x1; }
                    uint8_t get_group_address_list(int i) const { return i < 0 or i > length/2 ? 0 : ntohs(*(group_address_list + i)); }
                };

                class DomainAddressSerialNumber
                {
                    const uint8_t* serial_number;
                    const uint8_t* domain_address;
                public:
                    constexpr static const uint8_t ser_num_size = 6;
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length);

                    uint8_t get_serial_number(int i) const { return i >= ser_num_size ? 0 : serial_number[i]; }
                    uint8_t get_domain_address(int i) const { return i < 0 or i > length ? 0 : *(domain_address + i); }
                };

                /* FIXME: implement error handling */
                class FileStream
                {
                    const uint8_t* file;
                    const uint8_t* file_block;
                public:
                    uint8_t length;
                    void load(const snort::Packet& p, int& offset, uint8_t information_length);

                    uint8_t get_file_handle() const { return ((*file) & 0xf0) >> 4; }
                    uint8_t get_file_block_seqnum() const { return (*file) & 0xf; }
                    uint8_t get_file_block(int i) const { return i > 0 or i > length ? 0 : *(file_block + i); }
                };

            }

            class APDU
            {
                const uint16_t* apci;
            public:
                union {
                    apdu::GroupValue group_value;
                    apdu::IndividualAddress individual_address;
                    apdu::ADC adc;
                    apdu::SystemNetworkParameter system_network_parameter;
                    apdu::Memory memory;
                    apdu::UserMemory user_memory;
                    apdu::UserMemoryBit user_memory_bit;
                    apdu::UserManufacturerInfo user_manufacturer_info;
                    apdu::FunctionPropertyCommand function_property_command;
                    apdu::FunctionPropertyState function_property_state;
                    apdu::DeviceDescriptor device_descriptor;
                    apdu::Restart restart;
                    apdu::MemoryBit memory_bit;
                    apdu::Authorize authorize;
                    apdu::Key key;
                    apdu::PropertyValue property_value;
                    apdu::PropertyDescription property_description;
                    apdu::NetworkParameter network_parameter;
                    apdu::IndividualAddressSerialNumber indiv_addr_serial_number;
                    apdu::DomainAddress domain_address;
                    apdu::Link link;
                    apdu::DomainAddressSerialNumber dom_addr_serial_number;
                    apdu::FileStream file_stream;
                };

                void load(const snort::Packet& p, int& offset, uint8_t length, const knxnetip::module::server& server, const knxnetip::module::policy& policy);

                apdu::Type get_apci() const;
            };
        }
    }
}

#endif /* KNXNETIP_APDU_H */

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
// knxnetip_apdu.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_apdu.h"
#include "knxnetip_util.h"
#include "detection/detection_engine.h"
#include "knxnetip_module.h"
#include "knxnetip_tables.h"

std::map<knxnetip::packet::cemi::apdu::Type, std::string> knxnetip::packet::cemi::apdu::app_service_identifier
{
    { knxnetip::packet::cemi::apdu::Type::A_GroupValue_Read, "A_GroupValue_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_GroupValue_Response, "A_GroupValue_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_GroupValue_Write, "A_GroupValue_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_IndividualAddress_Write, "A_IndividualAddress_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_IndividualAddress_Read, "A_IndividualAddress_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_IndividualAddress_Response, "A_IndividualAddress_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_ADC_Read, "A_ADC_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_ADC_Response, "A_ADC_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_SystemNetworkParameter_Read, "A_SystemNetworkParameter_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_SystemNetworkParameter_Response, "A_SystemNetworkParameter_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_SystemNetworkParameter_Write, "A_SystemNetworkParameter_Write" },
    { knxnetip::packet::cemi::apdu::Type::planned, "planned" },
    { knxnetip::packet::cemi::apdu::Type::A_Memory_Read, "A_Memory_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_Memory_Response, "A_Memory_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_Memory_Write, "A_Memory_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_UserMemory_Read, "A_UserMemory_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_UserMemory_Response, "A_UserMemory_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_UserMemory_Write, "A_UserMemory_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_UserMemoryBit_Write, "A_UserMemoryBit_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_UserManufacturerInfo_Read, "A_UserManufacturerInfo_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_UserManufacturerInfo_Response, "A_UserManufacturerInfo_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_FunctionPropertyCommand, "A_FunctionPropertyCommand" },
    { knxnetip::packet::cemi::apdu::Type::A_FunctionPropertyState_Read, "A_FunctionPropertyState_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_FunctionPropertyState_Response, "A_FunctionPropertyState_Response" },
    { knxnetip::packet::cemi::apdu::Type::reserved_UserMsg_S, "reserved_UserMsg_S" },
    { knxnetip::packet::cemi::apdu::Type::reserved_UserMsg_E, "reserved_UserMsg_E" },
    { knxnetip::packet::cemi::apdu::Type::reserved_UserMsg_Manu_S, "reserved_UserMsg_Manu_S" },
    { knxnetip::packet::cemi::apdu::Type::reserved_UserMsg_Manu_E, "reserved_UserMsg_Manu_E" },
    { knxnetip::packet::cemi::apdu::Type::A_DeviceDescriptor_Read, "A_DeviceDescriptor_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_DeviceDescriptor_Response, "A_DeviceDescriptor_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_Restart, "A_Restart" },
    // A_Restart_Response = 0x381,
    { knxnetip::packet::cemi::apdu::Type::A_Open_Routing_Table_Req, "A_Open_Routing_Table_Req" },
    { knxnetip::packet::cemi::apdu::Type::A_Read_Routing_Table_Req, "A_Read_Routing_Table_Req" },
    { knxnetip::packet::cemi::apdu::Type::A_Read_Routing_Table_Res, "A_Read_Routing_Table_Res" },
    { knxnetip::packet::cemi::apdu::Type::A_Write_Routing_Table_Req, "A_Write_Routing_Table_Req" },
    { knxnetip::packet::cemi::apdu::Type::A_Read_Router_Memory_Req, "A_Read_Router_Memory_Req" },
    { knxnetip::packet::cemi::apdu::Type::A_Read_Router_Memory_Res, "A_Read_Router_Memory_Res" },
    { knxnetip::packet::cemi::apdu::Type::A_Write_Router_Memory_Req, "A_Write_Router_Memory_Req" },
    { knxnetip::packet::cemi::apdu::Type::A_Read_Router_Status_Req, "A_Read_Router_Status_Req" },
    { knxnetip::packet::cemi::apdu::Type::A_Read_Router_Status_Res, "A_Read_Router_Status_Res" },
    { knxnetip::packet::cemi::apdu::Type::A_Write_Router_Status_Req, "A_Write_Router_Status_Req" },
    { knxnetip::packet::cemi::apdu::Type::A_MemoryBit_Write, "A_MemoryBit_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_Authorize_Request, "A_Authorize_Request" },
    { knxnetip::packet::cemi::apdu::Type::A_Authorize_Response, "A_Authorize_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_Key_Write, "A_Key_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_Key_Response, "A_Key_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_PropertyValue_Read, "A_PropertyValue_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_PropertyValue_Response, "A_PropertyValue_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_PropertyValue_Write, "A_PropertyValue_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_PropertyDescription_Read, "A_PropertyDescription_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_PropertyDescription_Response, "A_PropertyDescription_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_NetworkParameter_Read, "A_NetworkParameter_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_NetworkParameter_Response, "A_NetworkParameter_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_IndividualAddressSerialNumber_Read, "A_IndividualAddressSerialNumber_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_IndividualAddressSerialNumber_Respone, "A_IndividualAddressSerialNumber_Respone" },
    { knxnetip::packet::cemi::apdu::Type::A_IndividualAddressSerialNumber_Write, "A_IndividualAddressSerialNumber_Write" },
    { knxnetip::packet::cemi::apdu::Type::reserved, "reserved" },
    { knxnetip::packet::cemi::apdu::Type::A_DomainAddress_Write, "A_DomainAddress_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_DomainAddress_Read, "A_DomainAddress_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_DomainAddress_Response, "A_DomainAddress_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_DomainAddressSelective_Read, "A_DomainAddressSelective_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_NetworkParameter_Write, "A_NetworkParameter_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_Link_Read, "A_Link_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_Link_Response, "A_Link_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_Link_Write, "A_Link_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_GroupPropValue_Read, "A_GroupPropValue_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_GroupPropValue_Response, "A_GroupPropValue_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_GroupPropValue_Write, "A_GroupPropValue_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_GroupPropValue_InfoReport, "A_GroupPropValue_InfoReport" },
    { knxnetip::packet::cemi::apdu::Type::A_DomainAddressSerialNumber_Read, "A_DomainAddressSerialNumber_Read" },
    { knxnetip::packet::cemi::apdu::Type::A_DomainAddressSerialNumber_Response, "A_DomainAddressSerialNumber_Response" },
    { knxnetip::packet::cemi::apdu::Type::A_DomainAddressSerialNumber_Write, "A_DomainAddressSerialNumber_Write" },
    { knxnetip::packet::cemi::apdu::Type::A_FileStream_InfoReport, "A_FileStream_InfoReport" }
};

void knxnetip::packet::cemi::apdu::GroupValue::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    if (t == Type::A_GroupValue_Response or t == Type::A_GroupValue_Write)
    {
        if (information_length == 1)
        {
            offset -= 1;
            length = information_length;
        }
        else
        {
            length = information_length - 1;
        }

        util::get(data, p.data, offset, p.dsize, length);
    }
}

void knxnetip::packet::cemi::apdu::IndividualAddress::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    if (t == Type::A_IndividualAddress_Write)
    {
        util::get(address, p.data, offset, p.dsize);
    }
}

void knxnetip::packet::cemi::apdu::ADC::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    offset -= 1;

    util::get(channel_nr, p.data, offset, p.dsize);
    util::get(read_count, p.data, offset, p.dsize);

    if (t == Type::A_ADC_Response)
    {
        util::get(sum, p.data, offset, p.dsize);
    }
}

void knxnetip::packet::cemi::apdu::SystemNetworkParameter::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    util::get(object_type, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);
    length = information_length - sizeof(*object_type) - sizeof(*property_id) - 1;
    util::get(test_info, p.data, offset, p.dsize, length);
}

void knxnetip::packet::cemi::apdu::Memory::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    offset -= 1;
    util::get(number, p.data, offset, p.dsize);
    util::get(address, p.data, offset, p.dsize);

    if (t == Type::A_Memory_Response or t == Type::A_Memory_Write)
    {
        util::get(data, p.data, offset, p.dsize, get_number());
    }
}

void knxnetip::packet::cemi::apdu::UserMemory::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    util::get(addr_num, p.data, offset, p.dsize);
    util::get(address, p.data, offset, p.dsize);

    if (t == Type::A_UserMemory_Response or t == Type::A_UserMemory_Write)
    {
        util::get(data, p.data, offset, p.dsize, get_number());
    }
}

void knxnetip::packet::cemi::apdu::UserMemoryBit::load(const snort::Packet& p, int& offset)
{
    util::get(number, p.data, offset, p.dsize);
    util::get(address, p.data, offset, p.dsize);
    util::get(and_data, p.data, offset, p.dsize, get_number());
    util::get(xor_data, p.data, offset, p.dsize, get_number());
}

void knxnetip::packet::cemi::apdu::UserManufacturerInfo::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    if (t == Type::A_UserManufacturerInfo_Response)
    {
        util::get(manufacturer_id, p.data, offset, p.dsize);
        util::get(manufacturer_specific, p.data, offset, p.dsize, man_spec_size);
    }
}

void knxnetip::packet::cemi::apdu::FunctionPropertyCommand::load(const snort::Packet& p, int& offset, uint8_t information_length)
{
    util::get(object_index, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);

    length = information_length - sizeof(*object_index) - sizeof(*property_id) - 1;
    if (length > 0)
    {
        util::get(data, p.data, offset, p.dsize, length);
    }
}

void knxnetip::packet::cemi::apdu::FunctionPropertyState::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    util::get(object_index, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);

    if (t == Type::A_FunctionPropertyState_Response)
    {
        util::get(return_code, p.data, offset, p.dsize);
        information_length -= 1;
    }

    length = information_length - sizeof(*object_index) - sizeof(*property_id) - 1;
    util::get(data, p.data, offset, p.dsize, length);
}

void knxnetip::packet::cemi::apdu::DeviceDescriptor::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    offset -= 1;
    util::get(descriptor_type, p.data, offset, p.dsize);
    length = information_length - 1;

    if (t == Type::A_DeviceDescriptor_Response)
    {
        util::get(device_descriptor, p.data, offset, p.dsize, information_length);
    }
}

void knxnetip::packet::cemi::apdu::Restart::load(const snort::Packet& p, int& offset)
{
    offset -= 1;
    util::get(data, p.data, offset, p.dsize);

    if (is_master_reset())
    {
        if (!is_response())
        {
            util::get(erase_code, p.data, offset, p.dsize);
            util::get(channel_nr, p.data, offset, p.dsize);
        }
        else
        {
            util::get(error_code, p.data, offset, p.dsize);
            util::get(process_time, p.data, offset, p.dsize);
        }
    }
}

void knxnetip::packet::cemi::apdu::MemoryBit::load(const snort::Packet& p, int& offset)
{
    util::get(number, p.data, offset, p.dsize);
    util::get(address, p.data, offset, p.dsize);
    util::get(and_data, p.data, offset, p.dsize, get_number());
    util::get(xor_data, p.data, offset, p.dsize, get_number());
}

void knxnetip::packet::cemi::apdu::Authorize::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    if (t == Type::A_Authorize_Request)
    {
        util::get(reserved, p.data, offset, p.dsize);
        if (*reserved != 0)
        {
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_RESERVED_FIELD_W_DATA);
        }
        util::get(key, p.data, offset, p.dsize);
    }
    else if (t == Type::A_ADC_Response)
    {
        util::get(level, p.data, offset, p.dsize);
    }
}

void knxnetip::packet::cemi::apdu::Key::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    util::get(level, p.data, offset, p.dsize);

    if (t == Type::A_Key_Response)
    {
        util::get(key, p.data, offset, p.dsize);
    }
}

void knxnetip::packet::cemi::apdu::PropertyValue::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    util::get(object_index, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);
    util::get(elem_six, p.data, offset, p.dsize);

    length = information_length - sizeof(*object_index) - sizeof(*property_id) - sizeof(*elem_six) - 1;
    if (t == Type::A_PropertyValue_Response or t == Type::A_PropertyValue_Write)
    {
        util::get(data, p.data, offset, p.dsize, length);
    }
}

void knxnetip::packet::cemi::apdu::PropertyDescription::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    util::get(object_index, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);
    util::get(property_index, p.data, offset, p.dsize);

    if (t == Type::A_PropertyDescription_Response)
    {
        util::get(type, p.data, offset, p.dsize);
        util::get(max_elem, p.data, offset, p.dsize);
        util::get(access, p.data, offset, p.dsize);
    }
}

void knxnetip::packet::cemi::apdu::NetworkParameter::load(const snort::Packet& p, int& offset, uint8_t information_length)
{
    util::get(object_type, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);
    length = information_length - sizeof(*object_type) - sizeof(property_id) - 1;
    util::get(test_info, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::apdu::IndividualAddressSerialNumber::load(const snort::Packet& p, int& offset, apdu::Type t)
{
    util::get(serial_number, p.data, offset, p.dsize, ser_num_size);

    if (t == Type::A_IndividualAddressSerialNumber_Respone)
    {
        util::get(domain_address, p.data, offset, p.dsize);
        util::get(reserved, p.data, offset, p.dsize); /* call for correct offset tracking */
    }
    else if (t == Type::A_IndividualAddressSerialNumber_Write)
    {
        util::get(domain_address, p.data, offset, p.dsize);
        util::get(reserved2, p.data, offset, p.dsize); /* call for correct offset tracking */
    }
}

void knxnetip::packet::cemi::apdu::DomainAddress::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    if (t == Type::A_DomainAddress_Read)
    {
        length = 0;
    }
    else if (t == Type::A_DomainAddress_Response or t == Type::A_DomainAddress_Write or
              t == Type::A_DomainAddressSelective_Read)
    {
        length = information_length - 1;
        util::get(domain_address, p.data, offset, p.dsize, length);
    }
}

void knxnetip::packet::cemi::apdu::Link::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    util::get(group_object_number, p.data, offset, p.dsize);
    util::get(addr_six, p.data, offset, p.dsize);

    length = information_length - sizeof(*group_object_number) - sizeof(*addr_six) - 1;
    num_group_addresses = length/2;

    if (t == Type::A_Link_Response)
    {
        util::get(group_address_list, p.data, offset, p.dsize);
        offset += num_group_addresses - 1;
    }
}

void knxnetip::packet::cemi::apdu::DomainAddressSerialNumber::load(const snort::Packet& p, int& offset, apdu::Type t, uint8_t information_length)
{
    util::get(serial_number, p.data, offset, p.dsize, ser_num_size);

    if (t == Type::A_DomainAddressSerialNumber_Read)
    {
        length = 0;
    }
    else if (t == Type::A_DomainAddressSerialNumber_Response or t == Type::A_DomainAddressSerialNumber_Write)
    {
        length = information_length - ser_num_size - 1;
        util::get(domain_address, p.data, offset, p.dsize, length);
    }
}

void knxnetip::packet::cemi::apdu::FileStream::load(const snort::Packet& p, int& offset, uint8_t information_length)
{
    util::get(file, p.data, offset, p.dsize);
    length = information_length - sizeof(*file) - 1;
    util::get(file_block, p.data, offset, p.dsize, length);
}

knxnetip::packet::cemi::apdu::Type knxnetip::packet::cemi::APDU::get_apci() const
{
    uint16_t apci4 = (ntohs(*apci) & 0x3c0) >> 6;
    uint16_t apci6 = ntohs(*apci) & 0x3f;

    if (apci4 == 0 and apci6 == 0)
    {
        return apdu::Type::A_GroupValue_Read;
    }
    // group response / write
    else if (apci4 == 1 or apci4 == 2)
    {
        return static_cast<apdu::Type>(apci4 << 6);
    }
    // individual address write / read / response
    else if (apci4 == 3 or apci4 == 4 or apci4 == 5)
    {
        if (apci6 == 0)
        {
            return static_cast<apdu::Type>((apci4 << 6) | apci6);
        }
    }
    // adc read / response
    else if (apci4 == 6 or apci4 == 7)
    {
        return static_cast<apdu::Type>(apci4 << 6);
    }
    //  memory read / response / write
    else if (apci4 == 8 or apci4 == 9 or apci4 == 10)
    {
        return static_cast<apdu::Type>(apci4 << 6);
    }
    // device descriptor read / response
    else if (apci4 == 12 or apci4 == 13)
    {
        return static_cast<apdu::Type>(apci4 << 6);
    }
    // restart
    else if (apci4 == 14)
    {
        return static_cast<apdu::Type>(apci4 << 6);
    }

    return static_cast<apdu::Type>(ntohs(*apci) & 0x3ff);
}

void knxnetip::packet::cemi::APDU::load(const snort::Packet& p, int& offset, uint8_t information_length)
{
    util::get(apci, p.data, offset, p.dsize);

    switch(get_apci())
    {
        case apdu::Type::A_GroupValue_Read:
        case apdu::Type::A_GroupValue_Response:
        case apdu::Type::A_GroupValue_Write:
            group_value.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::A_IndividualAddress_Write:
        case apdu::Type::A_IndividualAddress_Read:
        case apdu::Type::A_IndividualAddress_Response:
            individual_address.load(p, offset, get_apci());
            break;
        case apdu::Type::A_ADC_Read:
        case apdu::Type::A_ADC_Response:
            adc.load(p, offset, get_apci());
            break;

        case apdu::Type::A_SystemNetworkParameter_Read:
        case apdu::Type::A_SystemNetworkParameter_Response:
        case apdu::Type::A_SystemNetworkParameter_Write:
            system_network_parameter.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::planned:
            /* fall-through */
            /* planned for future system broadcast service */
            break;

        case apdu::Type::A_Memory_Read:
        case apdu::Type::A_Memory_Response:
        case apdu::Type::A_Memory_Write:
            memory.load(p, offset, get_apci());
            break;

        case apdu::Type::A_UserMemory_Read:
        case apdu::Type::A_UserMemory_Response:
        case apdu::Type::A_UserMemory_Write:
            user_memory.load(p, offset, get_apci());
            break;

        /* not for future use */
        case apdu::Type::A_UserMemoryBit_Write:
            user_memory_bit.load(p, offset);
            break;

        case apdu::Type::A_UserManufacturerInfo_Read:
        case apdu::Type::A_UserManufacturerInfo_Response:
            user_manufacturer_info.load(p, offset, get_apci());
            break;

        case apdu::Type::A_FunctionPropertyCommand:
            function_property_command.load(p, offset, information_length);
            break;

        case apdu::Type::A_FunctionPropertyState_Read:
        case apdu::Type::A_FunctionPropertyState_Response:
            function_property_state.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::reserved_UserMsg_S:
        case apdu::Type::reserved_UserMsg_E:
        case apdu::Type::reserved_UserMsg_Manu_S:
        case apdu::Type::reserved_UserMsg_Manu_E:
            /* fall-through */
            break;

        case apdu::Type::A_DeviceDescriptor_Read:
        case apdu::Type::A_DeviceDescriptor_Response:
            device_descriptor.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::A_Restart:
            restart.load(p, offset);
            break;

        /* Coupler specific services */
        /* not for future use */
        case apdu::Type::A_Open_Routing_Table_Req:
        case apdu::Type::A_Read_Routing_Table_Req:
        case apdu::Type::A_Read_Routing_Table_Res:
        case apdu::Type::A_Write_Routing_Table_Req:
        case apdu::Type::A_Read_Router_Memory_Req:
        case apdu::Type::A_Read_Router_Memory_Res:
        case apdu::Type::A_Write_Router_Memory_Req:
        case apdu::Type::A_Read_Router_Status_Req:
        case apdu::Type::A_Read_Router_Status_Res:
        case apdu::Type::A_Write_Router_Status_Req:
            /* fall-through */
            break;

        /* not for future use */
        case apdu::Type::A_MemoryBit_Write:
            memory_bit.load(p, offset);
            break;

        case apdu::Type::A_Authorize_Request:
        case apdu::Type::A_Authorize_Response:
            authorize.load(p, offset, get_apci());
            break;

        case apdu::Type::A_Key_Write:
        case apdu::Type::A_Key_Response:
            key.load(p, offset, get_apci());
            break;

        case apdu::Type::A_PropertyValue_Read:
        case apdu::Type::A_PropertyValue_Response:
        case apdu::Type::A_PropertyValue_Write:
            property_value.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::A_PropertyDescription_Read:
        case apdu::Type::A_PropertyDescription_Response:
            property_description.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::A_NetworkParameter_Read:
        case apdu::Type::A_NetworkParameter_Response:
            network_parameter.load(p, offset, information_length);
            break;

        case apdu::Type::A_IndividualAddressSerialNumber_Read:
        case apdu::Type::A_IndividualAddressSerialNumber_Respone:
        case apdu::Type::A_IndividualAddressSerialNumber_Write:
            indiv_addr_serial_number.load(p, offset, get_apci());
            break;

        /* not for future use (formerly: A_ServiceInformation_Indication) */
        case apdu::Type::reserved:
            /* fall-through */
            break;

        case apdu::Type::A_DomainAddress_Write:
        case apdu::Type::A_DomainAddress_Read:
        case apdu::Type::A_DomainAddress_Response:
        case apdu::Type::A_DomainAddressSelective_Read:
            domain_address.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::A_NetworkParameter_Write:
            network_parameter.load(p, offset, information_length);
            break;

        case apdu::Type::A_Link_Read:
        case apdu::Type::A_Link_Response:
        case apdu::Type::A_Link_Write:
            link.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::A_GroupPropValue_Read:
        case apdu::Type::A_GroupPropValue_Response:
        case apdu::Type::A_GroupPropValue_Write:
        case apdu::Type::A_GroupPropValue_InfoReport:
            /* fall-through */
            /* unspecified data structure */
            break;

        case apdu::Type::A_DomainAddressSerialNumber_Read:
        case apdu::Type::A_DomainAddressSerialNumber_Response:
        case apdu::Type::A_DomainAddressSerialNumber_Write:
            dom_addr_serial_number.load(p, offset, get_apci(), information_length);
            break;

        case apdu::Type::A_FileStream_InfoReport:
            file_stream.load(p, offset, information_length);
            break;

        default:
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_APP_SRVC_UNSUPPORTED);
            break;
    }
}

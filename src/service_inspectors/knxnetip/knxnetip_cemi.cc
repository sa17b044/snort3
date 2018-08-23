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
// knxnetip_cemi.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_cemi.h"
#include "knxnetip_util.h"
#include "detection/detection_engine.h"
#include "knxnetip_module.h"
#include "knxnetip_tables.h"


/* CEMI - Add. Info */
void knxnetip::packet::cemi::add_info::PlMediumInfo::load(const snort::Packet& p, int& offset)
{
    util::get(domain_address, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::RfMediumInfo::load(const snort::Packet& p, int& offset)
{
    util::get(rf_info, p.data, offset, p.dsize);
    util::get(serial_number, p.data, offset, p.dsize, ser_num_size);
    util::get(dl_frame_number, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::BusmonitorStatusInfo::load(const snort::Packet& p, int& offset)
{
    util::get(error_flags, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::TimestampRelative::load(const snort::Packet& p, int& offset)
{
    util::get(timestamp_rel, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::TimeDelayUntilSending::load(const snort::Packet& p, int& offset)
{
    util::get(time_delay, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::ExtendedRelativeTimestamp::load(const snort::Packet& p, int& offset)
{
    util::get(timestamp_dev_ind, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::BiBatInfo::load(const snort::Packet& p, int& offset)
{
    util::get(bibat_ctrl, p.data, offset, p.dsize);
    util::get(bibat_block, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::RfMultiInfo::load(const snort::Packet& p, int& offset)
{
    util::get(transmission_frequency, p.data, offset, p.dsize);
    util::get(call_channel, p.data, offset, p.dsize);
    util::get(fast_ack, p.data, offset, p.dsize);
    util::get(reception_frequency, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::PrePostamble::load(const snort::Packet& p, int& offset)
{
    util::get(preamble_length, p.data, offset, p.dsize);
    util::get(postamble_length, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::add_info::RfFastAckInfo::load(const snort::Packet& p, int& offset, uint8_t length)
{
    util::get(status, p.data, offset, p.dsize);
    util::get(info, p.data, offset, p.dsize);

    size = length/2;
    offset += (size * 2) - sizeof(*status) - sizeof(*info);
}

void knxnetip::packet::cemi::add_info::ManufacturerSpecificData::load(const snort::Packet& p, int& offset, uint8_t length)
{
    util::get(manufacturer_id, p.data, offset, p.dsize);
    util::get(subfunction, p.data, offset, p.dsize);
    util::get(data, p.data, offset, p.dsize);

    size = length - sizeof(*manufacturer_id) - sizeof(*subfunction) - sizeof(*data);
    offset += length;
}

void knxnetip::packet::cemi::AdditionalInformation::load(const snort::Packet& p, int& offset)
{
    util::get(type_id, p.data, offset, p.dsize);
    util::get(length, p.data, offset, p.dsize);

    switch(get_type_id())
    {
        case add_info::TypeId::PL_INFO:
            pl_medium_info.load(p, offset);
            break;

        case add_info::TypeId::RF_INFO:
            rf_medium_info.load(p, offset);
            break;

        case add_info::TypeId::BUSMON_INFO:
            bus_monitor_status_info.load(p, offset);
            break;

        case add_info::TypeId::TIME_REL:
            timestamp_relative.load(p, offset);
            break;

        case add_info::TypeId::TIME_DELAY:
            time_delay_until_send.load(p, offset);
            break;

        case add_info::TypeId::EXEND_TIME:
            extended_relative_timestamp.load(p, offset);
            break;

        case add_info::TypeId::BIBAT_INFO:
            bibat_info.load(p, offset);
            break;

        case add_info::TypeId::RF_MULTI:
            rf_mulfi_info.load(p, offset);
            break;

        case add_info::TypeId::PREAMBEL:
            pre_postamble.load(p, offset);
            break;

        case add_info::TypeId::RF_FAST_ACK:
            rf_fastack_info.load(p, offset, get_length());
            break;

        case add_info::TypeId::MANU_DATA:
            manufacturer_data.load(p, offset, get_length());
            break;

        default:
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            break;
    }
}

/* CEMI - TPDU */
void knxnetip::packet::cemi::TPDU::load(const snort::Packet& p, int& offset)
{
    util::get(information_length, p.data, offset, p.dsize);

    if (get_info_length() > 0)
    {
        apdu.load(p, offset, get_info_length());
    }
}

/* CEMI - NPDU */
void knxnetip::packet::cemi::NPDU::load(const snort::Packet& p, int& offset)
{
    util::get(information_length, p.data, offset, p.dsize);
    util::get(tpci, p.data, offset, p.dsize);

    if (get_info_length() > 0)
    {
        offset -= 1;
        apdu.load(p, offset, get_info_length());
    }
}

/* CEMI - Data Link */
void knxnetip::packet::cemi::datalink::Data::load(const snort::Packet& p, int& offset)
{
    util::get(control_field_1, p.data, offset, p.dsize);
    util::get(control_field_2, p.data, offset, p.dsize);
    util::get(source_address, p.data, offset, p.dsize);
    util::get(destination_address, p.data, offset, p.dsize);
    npdu.load(p, offset);
}

void knxnetip::packet::cemi::datalink::PollData::load(const snort::Packet& p, int& offset, MessageCode mc)
{
    util::get(control_field_1, p.data, offset, p.dsize);
    util::get(control_field_2, p.data, offset, p.dsize);
    util::get(source_address, p.data, offset, p.dsize);
    util::get(destination_address, p.data, offset, p.dsize);
    util::get(number_of_slots, p.data, offset, p.dsize);

    if (mc == cemi::MessageCode::L_POLL_DATA_CON)
    {
        util::get(poll_data, p.data, offset, p.dsize, get_number_of_slots());
    }
}

void knxnetip::packet::cemi::datalink::Raw::load(const snort::Packet& p, int& offset)
{
    util::get(raw_data, p.data, offset, p.dsize, p.dsize - offset);
}

void knxnetip::packet::cemi::DataLink::load(const snort::Packet& p, int& offset, MessageCode mc)
{
    switch(mc)
    {
        case cemi::MessageCode::L_DATA_REQ:
        case cemi::MessageCode::L_DATA_CON:
        case cemi::MessageCode::L_DATA_IND:
            data.load(p, offset);
            break;

        case cemi::MessageCode::L_POLL_DATA_REQ:
        case cemi::MessageCode::L_POLL_DATA_CON:
            poll_data.load(p, offset, mc);
            break;

        case cemi::MessageCode::L_RAW_REQ:
        case cemi::MessageCode::L_RAW_CON:
        case cemi::MessageCode::L_RAW_IND:
        case cemi::MessageCode::L_BUSMON_IND:
            raw.load(p, offset);
            break;

        default:
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            break;
    }
}

/* CEMI - Transport */
void knxnetip::packet::cemi::Transport::load(const snort::Packet& p, int& offset)
{
    util::get(reserved, p.data, offset, p.dsize, reserved_size);
    tpdu.load(p, offset);
}

/* CEMI - Device Mgmt */
void knxnetip::packet::cemi::devmgmt::DataProperty::load(const snort::Packet& p, int& offset, MessageCode mc, uint16_t body_length)
{
    util::get(interface_object_type, p.data, offset, p.dsize);
    util::get(object_instance, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);
    util::get(number_of_elements, p.data, offset, p.dsize);
    util::get(start_index, p.data, offset, p.dsize);
}

void knxnetip::packet::cemi::devmgmt::FunctionProperty::load(const snort::Packet& p, int& offset, MessageCode mc, uint16_t body_length)
{
    util::get(interface_object_type, p.data, offset, p.dsize);
    util::get(object_instance, p.data, offset, p.dsize);
    util::get(property_id, p.data, offset, p.dsize);

    if ( mc == cemi::MessageCode::M_FUNCPROPCOM_CON )
    {
        util::get(return_code, p.data, offset, p.dsize);
    }
}

void knxnetip::packet::cemi::DeviceManagement::load(const snort::Packet& p, int& offset, MessageCode mc, uint16_t body_length)
{
    switch(mc)
    {
        /* Data Property */
        case cemi::MessageCode::M_PROPREAD_REQ:
        case cemi::MessageCode::M_PROPREAD_CON:
        case cemi::MessageCode::M_PROPWRITE_REQ:
        case cemi::MessageCode::M_PROPWRITE_CON:
        case cemi::MessageCode::M_PROPINFO_IND:
            dp.load(p, offset, mc, body_length);
            break;

        /* Function Property */
        case cemi::MessageCode::M_FUNCPROPCOM_REQ:
        case cemi::MessageCode::M_FUNCPROPCOM_CON: // M_FUNCPROPSTATREAD_CON
        case cemi::MessageCode::M_FUNCPROPSTATREAD_REQ:
            fp.load(p, offset, mc, body_length);
            break;

        case cemi::MessageCode::M_RESET_REQ:
        case cemi::MessageCode::M_RESET_IND:
            break;

        default:
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
    }

    /* Data available */
    if (offset < p.dsize)
    {
        if (mc == MessageCode::M_RESET_REQ or mc == MessageCode::M_RESET_IND)
        {
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
        }
        else if (devmgmt::DataProperty::is_error_response(mc, dp.get_number_of_elements()))
        {
            length = 1;
            util::get(data, p.data, offset, p.dsize);
        }
        else
        {
            length = p.dsize - offset;
            util::get(data, p.data, offset, p.dsize, length);
        }
    }
    /* No data available */
    else
    {
        length = 0;

        if (devmgmt::DataProperty::is_error_response(mc, dp.get_number_of_elements()) or
            mc == MessageCode::M_PROPREAD_CON or mc == MessageCode::M_PROPWRITE_REQ or
            mc == MessageCode::M_PROPINFO_IND)
        {
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
        }
    }
}

/* CEMI */
void knxnetip::packet::CEMI::load(const snort::Packet& p, int& offset, uint16_t body_length)
{
    util::get(message_code, p.data, offset, p.dsize);

    /* Device Management */
    if (is_device_management())
    {
        device_mgmt.load(p, offset, get_message_code(), body_length);
    }
    else
    {
        util::get(additional_info_length, p.data, offset, p.dsize);

        /* Additional Information (optional) */
        if (get_additional_info_length() > 0)
        {
            additional_information.load(p, offset);
        }

        switch(get_message_code())
        {
            /* Data Link */
            case cemi::MessageCode::L_DATA_REQ:
            case cemi::MessageCode::L_DATA_CON:
            case cemi::MessageCode::L_DATA_IND:
            case cemi::MessageCode::L_POLL_DATA_REQ:
            case cemi::MessageCode::L_POLL_DATA_CON:
            case cemi::MessageCode::L_RAW_REQ:
            case cemi::MessageCode::L_RAW_CON:
            case cemi::MessageCode::L_RAW_IND:
            case cemi::MessageCode::L_BUSMON_IND:
                data_link.load(p, offset, get_message_code());
                break;

            case cemi::MessageCode::T_DATA_CONNEC_REQ:
            case cemi::MessageCode::T_DATA_CONNEC_IND:
            case cemi::MessageCode::T_DATA_INDV_REQ:
            case cemi::MessageCode::T_DATA_INDV_IND:
                transport.load(p, offset);
                break;

            default:
                /*FIXME: alert */
                snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
                break;
        }
    }
}

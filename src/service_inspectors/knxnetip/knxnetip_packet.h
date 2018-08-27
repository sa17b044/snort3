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
// knxnetip_packet.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_PACKET_H
#define KNXNETIP_PACKET_H

#include <arpa/inet.h>
#include <cstdint>
#include <memory>
#include "protocols/packet.h"
#include "knxnetip_enum.h"
#include "knxnetip_packet_util.h"
#include "knxnetip_cemi.h"

namespace knxnetip
{
    namespace packet
    {
        class Header
        {
            const uint8_t length;
            const uint8_t version;
            const uint16_t service_type;
            const uint16_t total_length;

        public:
            const uint8_t get_length() const { return length; }
            const uint8_t get_version() const { return version; }
            const knxnetip::ServiceType get_service_type() const { return static_cast<const knxnetip::ServiceType>(ntohs(service_type)); }
            const uint16_t get_total_length() const { return ntohs(total_length); }
            const uint16_t get_body_length() const { return get_total_length() - get_length(); }
        };

        enum class ErrorCode : uint8_t {
            E_NO_ERROR = 0x00,
            E_HOST_PROTOCOL_TYPE = 0x01,
            E_VERSION_NOT_SUPPORTED = 0x02,
            E_SEQUENCE_NUMBER = 0x04
        };

        struct SearchRequest
        {
            knxnetip::packet::HPAI discovery_endpoint;

            void load(const snort::Packet& p, int& offset);
        };

        struct SearchResponse
        {
            knxnetip::packet::HPAI control_endpoint;
            knxnetip::packet::DIB device_hardware;
            knxnetip::packet::DIB supported_service_families;

            void load(const snort::Packet& p, int& offset);
        };

        struct DescriptionRequest
        {
            knxnetip::packet::HPAI control_endpoint;

            void load(const snort::Packet& p, int& offset);
        };

        class DescriptionResponse
        {
            const uint8_t* additional_dibs;
            uint8_t additional_dib_length;
        public:
            knxnetip::packet::DIB device_hardware;
            knxnetip::packet::DIB supported_service_families;

            void load(const snort::Packet& p, int& offset, int body_length);
            knxnetip::packet::DIB get_add_dib(int i) const;
        };

        struct ConnectRequest
        {
            knxnetip::packet::HPAI control_endpoint;
            knxnetip::packet::HPAI data_endpoint;
            knxnetip::packet::CRI connection_req_info;

            void load(const snort::Packet& p, int& offset);
        };

        class ConnectResponse
        {
            const uint8_t* communication_channel_id;
            const uint8_t* connection_status;

        public:
            enum class ErrorCode : uint8_t {
                E_NO_ERROR = 0x00,
                E_CONNECTION_TYPE = 0x22,
                E_CONNECTION_OPTION = 0x23,
                E_NO_MORE_CONNECTIONS = 0x24
            };

            knxnetip::packet::HPAI data_endpoint;
            knxnetip::packet::CRD connection_res_dblock;

            void load(const snort::Packet& p, int& offset);

            uint8_t get_communication_channel_id() const { return *communication_channel_id; }
            ErrorCode get_connection_status() const { return static_cast<ErrorCode>(*connection_status); }
        };

        class ConnectionStateRequest
        {
            const uint8_t* communication_channel_id;
            const uint8_t* reserved;

        public:
            knxnetip::packet::HPAI control_endpoint;

            void load(const snort::Packet& p, int& offset);

            uint8_t get_communication_channel_id() const { return *communication_channel_id; }

        };

        class ConnectionStateResponse
        {
            const uint8_t *communication_channel_id;
            const uint8_t *status;

        public:
            enum class ErrorCode : uint8_t {
                E_NO_ERROR = 0x00,
                E_CONNECTION_ID = 0x21,
                E_DATA_CONNECTION = 0x26,
                E_KNX_CONNECTION = 0x27
            };

            void load(const snort::Packet& p, int& offset);

            uint8_t get_communication_channel_id() const { return *communication_channel_id; }
            uint8_t get_status() const { return *status; }
        };

        class DisconnectRequest
        {
            const uint8_t* communication_channel_id;
            const uint8_t* reserved;

        public:
            knxnetip::packet::HPAI control_endpoint;

            void load(const snort::Packet& p, int& offset);

            uint8_t get_communication_channel_id() const { return *communication_channel_id; }
        };

        class DisconnectResponse
        {
            const uint8_t* communication_channel_id;
            const uint8_t* status;

        public:
            void load(const snort::Packet& p, int& offset);

            uint8_t get_communication_channel_id() const { return *communication_channel_id; }
            uint8_t get_status() const { return *status; }
        };

        class DeviceConfigurationRequest
        {
        public:
            knxnetip::packet::ConnectionHeader connection_header;
            knxnetip::packet::CEMI cemi_frame;

            void load(const snort::Packet& p, int& offset, int body_length);
        };

        class DeviceConfigurationAcknowledge
        {
        public:
            enum class ErrorCode : uint8_t {
                E_NO_ERROR = 0x00
            };

            knxnetip::packet::ConnectionHeader connection_header;

            void load(const snort::Packet& p, int& offset);
        };

        class TunnellingRequest
        {
        public:
            knxnetip::packet::ConnectionHeader connection_header;
            knxnetip::packet::CEMI cemi_frame;

            void load(const snort::Packet& p, int& offset, int body_length);
        };

        class TunnellingAcknowledge
        {
        public:
            enum class ErrorCode : uint8_t {
                E_NO_ERROR = 0x00,
                E_TUNNELLING_LAYER = 0x29
            };

            knxnetip::packet::ConnectionHeader connection_header;

            void load(const snort::Packet& p, int& offset);
        };

        class RoutingIndication
        {
        public:
            knxnetip::packet::CEMI cemi_frame;

            void load(const snort::Packet& p, int& offset, int body_length);
        };

        class RoutingLost
        {
            const uint8_t* structure_length;
            const uint8_t* device_state;
            const uint16_t* number_of_lost_messages;
        public:
            void load(const snort::Packet& p, int& offset);
        };

        class RoutingBusy
        {
            const uint8_t* structure_length;
            const uint8_t* device_state;
            const uint16_t* routing_busy_wait_time; /* in ms */
            const uint16_t* routing_busy_control_field;
        public:

            void load(const snort::Packet& p, int& offset);
        };

        class RemoteDiagnosticRequest
        {
        public:
            knxnetip::packet::HPAI discovery_endpoint;
            knxnetip::packet::SELECTOR selector;

            void load(const snort::Packet& p, int& offset);
        };

        class RemoteDiagnosticResponse
        {
        public:
            knxnetip::packet::SELECTOR selector;

        private:
            const uint8_t* dibs;
            uint8_t dib_length;

        public:

            void load(const snort::Packet& p, int& offset, int body_length);

            knxnetip::packet::DIB get_dib(int i) const;
        };

        class RemoteBasicConfigurationRequest
        {
        public:
            knxnetip::packet::HPAI discovery_endpoint;
            knxnetip::packet::SELECTOR selector;

        private:
            const uint8_t* dibs;
            uint8_t dib_length;

        public:

            void load(const snort::Packet& p, int& offset, int body_length);

            knxnetip::packet::DIB get_dib(int i) const;
        };

        class RemoteResetRequest
        {
        public:
            knxnetip::packet::SELECTOR selector;

        private:
            const uint8_t* reset_command;
            const uint8_t* reserved;

        public:

            void load(const snort::Packet& p, int& offset);

            uint8_t get_reset_command() const { return *reset_command; }
        };

        class SecureWrapper
        {
            const uint16_t* secure_channel_index;
            const uint8_t* sequence_identifier;
            const uint8_t* encrypted_data;
        public:
            uint8_t length;
            constexpr static const uint8_t seq_iden_size = 6;
            void load(const snort::Packet& p, int& offset);

            uint16_t get_secure_channel_index() const { return ntohs(*secure_channel_index); }
            uint8_t get_sequence_identifier(int i) const { return i < 0 or i > seq_iden_size ? 0 : *(sequence_identifier + i); }
            uint8_t get_encrypted_data(int i) const { return i < 0 or i > length ? 0 : *(encrypted_data + i); }
        };

        class SecureChannelRequest
        {
            const uint8_t* client_public_value;
        public:
            constexpr static const uint8_t pub_val_size = 36;
            knxnetip::packet::HPAI control_endpoint;
            void load(const snort::Packet& p, int& offset);

            uint8_t get_client_public_value(int i) const { return i < 0 or i > pub_val_size ? 0 : *(client_public_value + i); }
        };

        class SecureChannelResponse
        {
            const uint16_t* secure_channel_index;
            const uint8_t* server_public_value;
            const uint8_t* message_auth_code; // encrypted
        public:
            constexpr static const uint8_t pub_val_size = 36;
            constexpr static const uint8_t msg_aut_size = 16;
            void load(const snort::Packet& p, int& offset);

            uint16_t get_secure_channel_index() const { return ntohs(*secure_channel_index); }
            uint8_t get_server_public_value(int i) const { return i < 0 or i > pub_val_size ? 0 : *(server_public_value + i); }
            uint8_t get_message_authentication_code(int i) const { return i < 0 or i > msg_aut_size ? 0 : *(message_auth_code + i); }
        };

        class SecureChannelAuthorize
        {
            const uint16_t* authorize_context;
            const uint8_t* message_auth_code;
        public:
            constexpr static const uint8_t msg_aut_size = 16;
            void load(const snort::Packet& p, int& offset);

            uint16_t get_authorize_context() const { return ntohs(*authorize_context); }
            uint8_t get_message_authentication_code(int i) const { return i < 0 or i > msg_aut_size ? 0 : *(message_auth_code + i); }
        };

        class SecureChannelStatus
        {
            const uint8_t* status;
            const uint8_t* reserved;
        public:
            enum class StatusCode : uint8_t {
                AUTHORIZATION_SUCCESS = 0x00,
                AUTHORIZATION_FAILED = 0x01,
                ERROR_UNAUTHORIZED = 0x02,
                TIMEOUT = 0x03
            };

            void load(const snort::Packet& p, int& offset);

            StatusCode get_status() const { return static_cast<StatusCode>(*status); }
        };

        class SecureGroupSyncRequest
        {
            const uint8_t* time_stamp;
            const uint8_t* message_auth_code;
        public:
            constexpr static const uint8_t time_st_size = 6;
            constexpr static const uint8_t msg_aut_size = 16;
            void load(const snort::Packet& p, int& offset);

            uint8_t get_time_stamp(int i) const { return i < 0 or i > time_st_size ? 0 : *(time_stamp + i); }
            uint8_t get_message_authentication_code(int i) const { return i < 0 or i > msg_aut_size ? 0 : *(message_auth_code + i); }
        };

        class SecureGroupSyncResponse
        {
            const uint8_t* time_stamp;
            const uint8_t* message_auth_code;
        public:
            constexpr static const uint8_t time_st_size = 6;
            constexpr static const uint8_t msg_aut_size = 16;
            void load(const snort::Packet& p, int& offset);

            uint8_t get_time_stamp(int i) const { return i < 0 or i > time_st_size ? 0 : *(time_stamp + i); }
            uint8_t get_message_authentication_code(int i) const { return i < 0 or i > msg_aut_size ? 0 : *(message_auth_code + i); }
        };
    }

    struct Packet
    {
        const packet::Header* h;
        union {
            packet::SearchRequest search_request;
            packet::SearchResponse search_response;
            packet::DescriptionRequest description_request;
            packet::DescriptionResponse description_response;
            packet::ConnectRequest connect_request;
            packet::ConnectResponse connect_response;
            packet::ConnectionStateRequest connection_state_request;
            packet::ConnectionStateResponse connection_state_response;
            packet::DisconnectRequest disconnect_request;
            packet::DisconnectResponse disconnect_response;
            packet::DeviceConfigurationRequest device_conf_request;
            packet::DeviceConfigurationAcknowledge device_conf_acknowledge;
            packet::TunnellingRequest tunnelling_request;
            packet::TunnellingAcknowledge tunnelling_acknowledge;
            packet::RoutingIndication routing_indication;
            packet::RoutingBusy routing_busy;
            packet::RoutingLost routing_lost;
            packet::RemoteDiagnosticRequest rem_diag_request;
            packet::RemoteDiagnosticResponse rem_diag_response;
            packet::RemoteBasicConfigurationRequest rem_basic_conf_request;
            packet::RemoteResetRequest rem_reset_request;
            packet::SecureWrapper sec_wrapper;
            packet::SecureChannelRequest sec_chan_request;
            packet::SecureChannelResponse sec_chan_response;
            packet::SecureChannelAuthorize sec_chan_authorize;
            packet::SecureChannelStatus sec_chan_status;
            packet::SecureGroupSyncRequest sec_group_sync_request;
            packet::SecureGroupSyncResponse sec_group_sync_response;
        };

        bool dissect(const snort::Packet& p, const knxnetip::module::server& server, const knxnetip::module::policy& policy);
    };

}

#endif /* KNXNETIP_PACKET_H */

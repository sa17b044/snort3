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
// knxnetip_dpt.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_dpt.h"

// DPT 2 Byte Float= (0.01 * m) * 2^e
static double get_2bytefloat(uint16_t v)
{
    // DPT Format: MEEEMMMM MMMMMMMMM
    // left align mantissa
    int m = ((v & 0x8000) << 16) | ((v & 0x7ff) << 20);
    // normalize
    m >>= 20;

    int exp = (v & 0x7800) >> 11;

    return (1 << exp) * m * 0.01;
}

bool knxnetip::dpt::is_dpt_higher(knxnetip::packet::cemi::apdu::GroupValue& gv, uint32_t dpt, double max)
{
    bool result = false;

    uint8_t main = (dpt & 0xffff0000) >> 16;

    switch (main)
    {
        /* DPT 1.+++ */
        case 1:
            break;

        /* DPT 2.+++ */
        case 2:
            break;

        /* DPT 3.+++ */
        case 3:
            break;

        /* DPT 4.+++ */
        case 4:
            break;

        /* DPT 5.+++ */
        case 5:
            break;

        /* DPT 6.+++ */
        case 6:
            break;

        /* DPT 7.+++ */
        case 7:
            break;

        /* DPT 8.+++ */
        case 8:
            break;

        /* DPT 9.+++ */
        case 9:
            if (gv.length == 2)
            {
                uint16_t v = ((uint16_t) gv.get_data(0)) << 8 | (uint16_t) gv.get_data(1);
                double dpt_val = get_2bytefloat(v);
                if ( dpt_val > max)
                {
                    result = true;
                }
            }
            break;

        default:
            break;
    }

    return result;
}

bool knxnetip::dpt::is_dpt_lower(knxnetip::packet::cemi::apdu::GroupValue& gv, uint32_t dpt, double min)
{
    bool result = false;

    uint8_t main = (dpt & 0xffff0000) >> 16;

    switch (main)
    {
        /* DPT 1.+++ */
        case 1:
            break;

        /* DPT 2.+++ */
        case 2:
            break;

        /* DPT 3.+++ */
        case 3:
            break;

        /* DPT 4.+++ */
        case 4:
            break;

        /* DPT 5.+++ */
        case 5:
            break;

        /* DPT 6.+++ */
        case 6:
            break;

        /* DPT 7.+++ */
        case 7:
            break;

        /* DPT 8.+++ */
        case 8:
            break;

        /* DPT 9.+++ */
        case 9:
            if (gv.length == 2)
            {
                uint16_t v = ((uint16_t) gv.get_data(0)) << 8 | (uint16_t) gv.get_data(1);
                double dpt_val = get_2bytefloat(v);
                if ( dpt_val < min)
                {
                    result = true;
                }
            }
            break;

        default:
            break;
    }

    return result;
}

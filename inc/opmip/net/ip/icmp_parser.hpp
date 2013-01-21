//=============================================================================
// Brief   : ICMP Parser
// Authors : Bruno Santos <bsantos@av.it.pt>
//           Sérgio Figueiredo <sfigueiredo@av.it.pt>
// ----------------------------------------------------------------------------
// OPMIP - Open Proxy Mobile IP
//
// Copyright (C) 2010-2012 Universidade de Aveiro
// Copyrigth (C) 2010-2012 Instituto de Telecomunicações - Pólo de Aveiro
//
// This software is distributed under a license. The full license
// agreement can be found in the file LICENSE in this distribution.
// This software may not be copied, modified, sold or distributed
// other than expressed in the named license agreement.
//
// This software is distributed without any warranty.
//=============================================================================

#ifndef OPMIP_PMIP_IP_ICMP_PARSER__HPP_
#define OPMIP_PMIP_IP_ICMP_PARSER__HPP_

///////////////////////////////////////////////////////////////////////////////
#include <opmip/base.hpp>
#include <opmip/net/ip/address.hpp>
#include <opmip/net/link/address_mac.hpp>

#include <vector>
#include <utility>

///////////////////////////////////////////////////////////////////////////////
namespace opmip { namespace net { namespace ip {

///////////////////////////////////////////////////////////////////////////////
bool icmp_rs_parse(uchar* buffer, size_t length, link::address_mac& source_link_layer);

struct icmp_mld_report_parser {
	typedef std::vector<address_v6>            source_list;
	typedef std::pair<address_v6, source_list> mcast_address;
	typedef std::vector<mcast_address>         mcast_address_list;

	bool parse(uchar* buffer, size_t length);

	std::vector<mcast_address> includes;
	std::vector<mcast_address> excludes;
	std::vector<mcast_address> change_to_includes;
	std::vector<mcast_address> change_to_excludes;
	std::vector<mcast_address> allow_new_sources;
	std::vector<mcast_address> block_old_sources;
};

///////////////////////////////////////////////////////////////////////////////
} /* namespace ip */ } /* namespace net */ } /* namespace opmip */

// EOF ////////////////////////////////////////////////////////////////////////
#endif /* OPMIP_PMIP_IP_ICMP_PARSER__HPP_ */

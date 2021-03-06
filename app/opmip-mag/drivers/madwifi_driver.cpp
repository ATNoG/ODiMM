//===========================================================================================================
// Brief   : MadWifi Driver
// Authors : Bruno Santos <bsantos@av.it.pt>
// Authors : Filipe Manco <filipe.manco@av.it.pt>
// ----------------------------------------------------------------------------------------------------------
// OPMIP - Open Proxy Mobile IP
//
// Copyright (C) 2010-2011 Universidade de Aveiro
// Copyrigth (C) 2010-2011 Instituto de Telecomunicações - Pólo de Aveiro
//
// This software is distributed under a license. The full license
// agreement can be found in the file LICENSE in this distribution.
// This software may not be copied, modified, sold or distributed
// other than expressed in the named license agreement.
//
// This software is distributed without any warranty.
//===========================================================================================================

#include "madwifi_driver.hpp"
#include <opmip/logger.hpp>
#include <opmip/sys/error.hpp>
#include <opmip/pmip/node_db.hpp>
#include <boost/bind.hpp>
#include <iostream>

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
namespace opmip { namespace app {

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
static opmip::logger log_("madwifi", std::cout);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
static void attach_result(const ll::mac_address& mn_address, const boost::system::error_code& ec)
{
	log_(0, "node ", mn_address, " attachment completed with code ", ec);
}

static void detach_result(const ll::mac_address& mn_address, const boost::system::error_code& ec)
{
	log_(0, "node ", mn_address, " detachment completed with code ", ec);
}

static void link_event(const boost::system::error_code& ec, const madwifi_driver::event& ev, pmip::mag& mag)
{
	if (ec)
		return;

	const opmip::pmip::mobile_node* mn = mag.get_node_database().find_mobile_node(ev.mn_address);

	if(!mn) {
		if (!mn) {
			log_(0, "node ", ev.mn_address, " not authorized");
			return;
		}
	}

	opmip::pmip::mag::attach_info ai(ev.if_index,
									 ev.if_address,
									 mn->id(),
									 ev.mn_address);

	switch (ev.which) {
	case opmip::app::madwifi_driver_impl::attach:
		mag.mobile_node_attach(ai, boost::bind(attach_result, ev.mn_address, _1));
		break;

	case opmip::app::madwifi_driver_impl::detach:
		mag.mobile_node_detach(ai, boost::bind(detach_result, ev.mn_address, _1));
		break;

	default:
		break;
	}
}

madwifi_driver::madwifi_driver(boost::asio::io_service& ios, pmip::mag& mag)
	: _impl(ios), _mag(mag)
{
}

madwifi_driver::~madwifi_driver()
{
}

void madwifi_driver::start(const std::vector<std::string>& options)
{
	boost::system::error_code ec;

	_impl.set_event_handler(boost::bind(link_event, _1, _2, boost::ref(_mag)));
	_impl.start(options, ec);
	sys::throw_on_error(ec);
}

void madwifi_driver::stop()
{
	boost::system::error_code ec;

	_impl.stop(ec);
	sys::throw_on_error(ec);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
} /* namespace app */ } /* namespace opmip */

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

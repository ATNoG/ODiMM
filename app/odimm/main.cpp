//===========================================================================================================
// Brief   : ODiMM - Open Distributed Mobility Management
// Authors : Bruno Santos <bsantos@av.it.pt>
// ----------------------------------------------------------------------------------------------------------
// OPMIP - Open Proxy Mobile IP
//
// Copyright (C) 2013 Universidade de Aveiro
// Copyrigth (C) 2013 Instituto de Telecomunicações - Pólo de Aveiro
//
// This software is distributed under a license. The full license
// agreement can be found in the file LICENSE in this distribution.
// This software may not be copied, modified, sold or distributed
// other than expressed in the named license agreement.
//
// This software is distributed without any warranty.
//===========================================================================================================

#include <opmip/base.hpp>
#include <opmip/debug.hpp>
#include <opmip/logger.hpp>
#include <opmip/exception.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
static opmip::logger log_("odimm", std::cout);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
static void signal_handler(const boost::system::error_code& error)
{
	log_(0, "quiting");
	//stop odimm code here
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char** argv)
{
	opmip::setup_crash_handler();

	try {
		size_t                       concurrency = boost::thread::hardware_concurrency();
		boost::asio::io_service      ios(concurrency);
		boost::asio::signal_set      sigs(ios, SIGINT, SIGTERM);

		sigs.async_wait(boost::bind(signal_handler, _1, drv, boost::ref(mag)));

		//start odimm code here

		boost::thread_group tg;
		for (size_t i = 1; i < concurrency; ++i)
			tg.create_thread(boost::bind(&boost::asio::io_service::run, &ios));

		ios.run();
		tg.join_all();

	} catch(opmip::exception& e) {
		std::cerr << e.what() << std::endl;
		return 1;

	} catch(std::exception& e) {
		std::cerr << "exception: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}

#include <boost/asio/impl/src.hpp>

// EOF //////////////////////////////////////////////////////////////////////////////////////////////////////

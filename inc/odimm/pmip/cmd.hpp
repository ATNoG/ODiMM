//=============================================================================
// Brief   : Central Mobility Database
// Authors : Bruno Santos <bsantos@av.it.pt>
// Authors : Filipe Manco <filipe.manco@av.it.pt>
// Authors : Daniel Santos <das@av.it.pt>
// ----------------------------------------------------------------------------
// OPMIP - Open Proxy Mobile IP
// ODiMM - Open Distributed Mobility Management
//
// Copyright (C) 2010-2013 Universidade de Aveiro
// Copyrigth (C) 2010-2013 Instituto de Telecomunicações - Pólo de Aveiro
//
// This software is distributed under a license. The full license
// agreement can be found in the file LICENSE in this distribution.
// This software may not be copied, modified, sold or distributed
// other than expressed in the named license agreement.
//
// This software is distributed without any warranty.
//=============================================================================

#ifndef OPMIP_PMIP_CMD__HPP_
#define OPMIP_PMIP_CMD__HPP_

///////////////////////////////////////////////////////////////////////////////
#include <odimm/base.hpp>
#include <odimm/chrono.hpp>
#include <odimm/logger.hpp>
#include <odimm/ip/mproto.hpp>
#include <odimm/pmip/bcache.hpp>
#include <odimm/pmip/node_db.hpp>
#include <odimm/pmip/mp_receiver.hpp>
#include <odimm/pmip/tunnels.hpp>
#include <odimm/sys/route_table.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/strand.hpp>
#include <odimm/pmip/bulist.hpp>

///////////////////////////////////////////////////////////////////////////////
namespace opmip { namespace pmip {

class error_category : public boost::system::error_category {
public:
	error_category()
	{ }

	const char* name() const;
	std::string message(int ev) const;
};

///////////////////////////////////////////////////////////////////////////////
class cmd {
	typedef boost::asio::io_service::strand strand;

public:
	class error_category : public boost::system::error_category {
	public:
		error_category()
		{ }

		const char* name() const;
		std::string message(int ev) const;
	};

	enum error_code {
		ec_success,
		ec_not_authorized,
		ec_unknown_lma,
		ec_invalid_state,
		ec_canceled,
		ec_timeout,
	};

public:
	typedef	ip::address_v6 ip_address;

	struct config {
		config()
			: min_delay_before_BCE_delete(10000),
			  max_delay_before_BCE_assign(1500)
		{ }

		uint min_delay_before_BCE_delete; //MinDelayBeforeBCEDelete (ms)
		uint max_delay_before_BCE_assign; //MaxDelayBeforeNewBCEAssign (ms)
	};

public:
	cmd(boost::asio::io_service& ios, node_db& ndb, size_t concurrency);

	void start(const std::string& id, bool tunnel_global_address);
	void stop();

private:
	void mp_send_handler(const boost::system::error_code& ec);
	void mp_receive_handler(const boost::system::error_code& ec, const proxy_binding_info& pbinfo, pbu_receiver_ptr& pbur, chrono& delay);

private:
	// TODO: change the implementation of the start_ method - remove data forwarding 
	// capabilities
	void start_(const std::string& id, bool tunnel_global_address);
	void stop_();

	// 1 - Receive PBU from S-MAAR
	//void receive_pbu_from_smaar();
	// 2 - Check/Update BCE
	//bcache_entry* 	check_update_bce(proxy_binding_info& pbinfo);
	// 3 - Send (Forward) PBU* to P-MAARs (proxy CoA) and updates P-CoA on BCE
	//void send_pbu_to_pmaar();
	// 4 - Receive PBA* from P-MAARs
	//void receive_pba_from_pmaar();
	// 5 - Update BCE with a P-MAAR list (additional field on BCE)
	//			Contains: one element for each P-MAAR involved in mobility of MN
	//				Contains: 	P-MAARs' global address
	//							Delegated prefi
	//void update_bce_with_pmaar_list();
	// 6 - Send PBA* tor S-MAAR
	//		Contains:	previous P-CoA
	//					prefix anchored to it embeded into a new mobility option (previous MAAR)
	//					(see 3.6.1 on draft)
	//void send_pba_to_smaar();
	//---------------------------------------------------------------------------------------
	// !Changed
	// The (3) following methods were introduced in order to provide the functionality of
	// parsing both PBUs and PBAs
	void proxy_binding_ack  (const proxy_binding_info& pbinfo, chrono& delay);
   	void proxy_binding_retry(const boost::system::error_code& ec, proxy_binding_info& pbinfo);
    void proxy_binding_renew(const boost::system::error_code& ec, const std::string& id);
	//---------------------------------------------------------------------------------------

	void 			proxy_binding_update(proxy_binding_info& pbinfo, chrono& delay);
	//!changed pbu_get_be to pbu_get_bce
	bcache_entry* 	pbu_get_bce(proxy_binding_info& pbinfo);
	bool          	pbu_maar_checkin(bcache_entry& be, proxy_binding_info& pbinfo);
	void          	pbu_process(proxy_binding_info& pbinfo);

	void expired_entry(const boost::system::error_code& ec, const std::string& mn_id);
	void remove_entry (const boost::system::error_code& ec, const std::string& mn_id);

	void add_route_entries(bcache_entry* be);
	void del_route_entries(bcache_entry* be);

private:
	strand   _service;
	bcache   _bcache;
	config   _config;
	node_db& _node_db;
	logger   _log;
	bulist   _bulist;

	ip::mproto::socket _mp_sock;

	std::string       _identifier;
	pmip::ip6_tunnels _tunnels;
	sys::route_table  _route_table;
	size_t            _concurrency;
};

///////////////////////////////////////////////////////////////////////////////
} /* namespace pmip */ } /* namespace odimm */

// EOF ////////////////////////////////////////////////////////////////////////
#endif /* OPMIP_PMIP_CMD__HPP_ */

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

#include <odimm/pmip/cmd.hpp>
#include <odimm/pmip/mp_sender.hpp>
#include <odimm/exception.hpp>
#include <boost/bind.hpp>
#include <iostream>

///////////////////////////////////////////////////////////////////////////////
namespace opmip { namespace pmip {

///////////////////////////////////////////////////////////////////////////////
bool validate_sequence_number(uint16 prev, uint16 current)
{
	return prev < 32768 ?
		((current > prev) && (current < (prev + 32768))) :
		((current > prev) || (current < (prev - 32768)));
}

///////////////////////////////////////////////////////////////////////////////
cmd::cmd(boost::asio::io_service& ios, node_db& ndb, size_t concurrency)
	: _service(ios), _node_db(ndb), _log("CMD", std::cout), _mp_sock(ios),
	  _tunnels(ios), _route_table(ios), _concurrency(concurrency)
{
}

void cmd::start(const std::string& id, bool tunnel_global_address)
{
	_service.dispatch(boost::bind(&cmd::start_, this, id, tunnel_global_address));
}

void cmd::stop()
{
	_service.dispatch(boost::bind(&cmd::stop_, this));
}

void cmd::mp_send_handler(const boost::system::error_code& ec)
{
	if (ec && ec != boost::system::errc::make_error_condition(boost::system::errc::operation_canceled))
		_log(0, "PBA sender error: ", ec.message());
}

void cmd::mp_receive_handler(const boost::system::error_code& ec, const proxy_binding_info& pbinfo, pbu_receiver_ptr& pbur, chrono& delay)
{
	if (ec) {
		if (ec != boost::system::errc::make_error_condition(boost::system::errc::operation_canceled))
			_log(0, "PBU receiver error: ", ec.message());
		return;
	}

	_service.dispatch(boost::bind(&cmd::proxy_binding_update, this, pbinfo, delay));
	pbur->async_receive(_mp_sock, boost::bind(&cmd::mp_receive_handler, this, _1, _2, _3, _4));
}

void cmd::start_(const std::string& id, bool tunnel_global_address)
{
	const router_node* node = _node_db.find_router(id);
	if (!node) {
		error_code ec(boost::system::errc::invalid_argument, boost::system::get_generic_category());

		throw_exception(exception(ec, "CMD id not found in node database"));
	}
	_log(0, "Started [id = ", id, ", address = ", node->address(), "]");

	_mp_sock.open(ip::mproto());
	_mp_sock.bind(ip::mproto::endpoint(node->address()));

	_identifier = id;

	//!Chanhed
	//_tunnels.open(ip::address_v6(node->address().to_bytes(), node->device_id()), tunnel_global_address);

	for (size_t i = 0; i < _concurrency; ++i) {
		pbu_receiver_ptr pbur(new pbu_receiver());

		pbur->async_receive(_mp_sock, boost::bind(&cmd::mp_receive_handler, this, _1, _2, _3, _4));
	}
}

void cmd::stop_()
{
	_bcache.clear();
	_mp_sock.close();
	_route_table.clear();
	//!Changed
	//_tunnels.close();
}


void cmd::proxy_binding_ack(const proxy_binding_info& pbinfo, chrono& delay)
{
	bulist_entry* be = _bulist.find(pbinfo.id);
	if (!be) {
		_log(0, "PBA error: binding update list entry not found [id = ", pbinfo.id, ", cmd = ", pbinfo.address, "]");
		return;
	}

	if (be->cmd_address() != pbinfo.address) {
		_log(0, "PBA error: not this CMD [id = ", pbinfo.id, ", cmd = ", pbinfo.address, "]");
		return;
	}

	if (pbinfo.status == ip::mproto::pba::status_bad_sequence) {
		_log(0, "PBA error: bad sequence number [id = ", pbinfo.id,
		                                      ", cmd = ", pbinfo.address,
		                                      ", sequence = ", be->sequence_number,
		                                      ", last accepted sequence = ", pbinfo.sequence, "]");

		be->sequence_number = pbinfo.sequence;

		proxy_binding_info pbinfo;

		pbinfo.id = be->mn_id();
		pbinfo.address = be->cmd_address();
		pbinfo.handoff = ip::mproto::option::handoff::k_unknown;
		pbinfo.sequence = ++be->sequence_number;
		pbinfo.lifetime = (be->bind_status != bulist_entry::k_bind_detach) ? be->lifetime : 0;
		pbinfo.prefix_list = be->mn_prefix_list();

		pbu_sender_ptr pbus(new pbu_sender(pbinfo));

		pbus->async_send(_mp_sock, boost::bind(&mag::mp_send_handler, this, _1));
		be->timer.cancel();
		be->timer.expires_from_now(boost::posix_time::milliseconds(1500));
		be->timer.async_wait(_service.wrap(boost::bind(&mag::proxy_binding_retry, this, _1, pbinfo)));

		return;
	}

	if (pbinfo.sequence != be->sequence_number) {
		_log(0, "PBA error: sequence number invalid [id = ", pbinfo.id,
		                                          ", cmd = ", pbinfo.address,
		                                          ", sequence = ", pbinfo.sequence,
		                                          " != ", be->sequence_number, "]");
		return;
	}

	if (pbinfo.lifetime && (be->bind_status == bulist_entry::k_bind_requested
		                    || be->bind_status == bulist_entry::k_bind_renewing)) {

		boost::system::error_code ec;

		if (pbinfo.status == ip::mproto::pba::status_ok) {
			if (be->bind_status == bulist_entry::k_bind_requested)
				add_route_entries(*be);
		} else {
			ec = boost::system::error_code(pbinfo.status, pba_error_category());
		}

		be->timer.cancel();
		be->handover_delay.stop();

		if (be->bind_status == bulist_entry::k_bind_requested) {
			report_completion(_service, be->completion, ec);
			_log(0, "PBA registration [delay = ", be->handover_delay.get(),
			                        ", id = ", pbinfo.id,
			                        ", cmd = ", pbinfo.address,
			                        ", status = ", pbinfo.status, "]");
		} else {
			_log(0, "PBA re-registration [delay = ", be->handover_delay.get(),
			                           ", id = ", pbinfo.id,
			                           ", cmd = ", pbinfo.address,
			                           ", status = ", pbinfo.status, "]");
		}


		be->bind_status = bulist_entry::k_bind_ack;

		if (pbinfo.status == ip::mproto::pba::status_ok) {
			//Will try to renew 3 seconds before binding expires or 1 second if lifetime <= 6
			uint expire = (pbinfo.lifetime <= 6) ? pbinfo.lifetime - 1 : pbinfo.lifetime - 3; //FIXME Check used values

			be->timer.expires_from_now(boost::posix_time::seconds(expire));
			be->timer.async_wait(_service.wrap(boost::bind(&mag::proxy_binding_renew, this, _1, pbinfo.id)));
		} else {
			_bulist.remove(be);
		}

		delay.stop();
		_log(0, "PBA register process delay ", delay.get());

	} else 	if (!pbinfo.lifetime && be->bind_status == bulist_entry::k_bind_detach) {
		boost::system::error_code ec;

		if (pbinfo.status == ip::mproto::pba::status_ok)
			ec = boost::system::error_code(pbinfo.status, pba_error_category());

		be->timer.cancel();
		be->handover_delay.stop();

		report_completion(_service, be->completion, ec);
		_log(0, "PBA de-registration [delay = ", be->handover_delay.get(),
		                           ", id = ", pbinfo.id,
		                           ", cmd = ", pbinfo.address, "]");

		_bulist.remove(be);

		delay.stop();
		_log(0, "PBA de-register process delay ", delay.get());

	} else {
		_log(0, "PBA ignored [id = ", pbinfo.id, ", cmd = ", pbinfo.address, ", status = ", be->bind_status, "]");
	}
}

void cmd::proxy_binding_retry(const boost::system::error_code& ec, proxy_binding_info& pbinfo)
{
	if (ec) {
		 if (ec != boost::system::errc::make_error_condition(boost::system::errc::operation_canceled))
			_log(0, "PBU retry timer error: ", ec.message());

		return;
	}

	bulist_entry* be = _bulist.find(pbinfo.id);
	if (!be || (be->bind_status != bulist_entry::k_bind_requested
		        && be->bind_status != bulist_entry::k_bind_renewing
			    && be->bind_status != bulist_entry::k_bind_detach)) {
		_log(0, "PBU retry error: binding update list entry not found [id = ", pbinfo.id, ", cmd = ", pbinfo.address, "]");
		return;
	}

	++be->retry_count;

	if (be->bind_status == bulist_entry::k_bind_detach && be->retry_count > 3) {
		report_completion(_service, be->completion, boost::system::error_code(ec_timeout, mag_error_category()));
		_log(0, "PBU retry error: max retry count [id = ", pbinfo.id, ", cmd = ", pbinfo.address, "]");
		_bulist.remove(be);
		return;
	}

	pbu_sender_ptr pbus(new pbu_sender(pbinfo));
	double         delay = std::min<double>(32, std::pow(1.5f, be->retry_count)); //FIXME: validate

	pbus->async_send(_mp_sock, boost::bind(&mag::mp_send_handler, this, _1));
	be->timer.expires_from_now(boost::posix_time::milliseconds(delay * 1000.f));
	be->timer.async_wait(_service.wrap(boost::bind(&mag::proxy_binding_retry, this, _1, pbinfo)));

	if (pbinfo.lifetime)
		_log(0, "PBU register retry [id = ", pbinfo.id,
			                      ", cmd = ", pbinfo.address,
			                      ", sequence = ", pbinfo.sequence,
			                      ", retry_count = ", uint(be->retry_count),
			                      ", delay = ", delay, "]");
	else
		_log(0, "PBU de-register retry [id = ", pbinfo.id,
			                         ", cmd = ", pbinfo.address,
			                         ", sequence = ", pbinfo.sequence,
			                         ", retry_count = ", uint(be->retry_count),
			                         ", delay = ", delay, "]");
}

void mag::proxy_binding_renew(const boost::system::error_code& ec, const std::string& id)
{
	if (ec) {
		 if (ec != boost::system::errc::make_error_condition(boost::system::errc::operation_canceled))
			_log(0, "PBU renew timer error: ", ec.message());

		return;
	}

	bulist_entry* be = _bulist.find(id);
	if (!be) {
		_log(0, "PBU renew timer error: binding update list entry not found [id = ", id, "]");
		return;
	}

	proxy_binding_info pbinfo;

	be->handover_delay.start(); //begin chrono handover delay
	pbinfo.id = be->mn_id();
	pbinfo.address = be->cmd_address();
	pbinfo.sequence = ++be->sequence_number;
	pbinfo.lifetime = be->lifetime;
	pbinfo.prefix_list = be->mn_prefix_list();
	pbinfo.handoff = ip::mproto::option::handoff::k_not_changed;
	pbu_sender_ptr pbus(new pbu_sender(pbinfo));

	be->bind_status = bulist_entry::k_bind_renewing;
	be->retry_count = 0;
	pbus->async_send(_mp_sock, boost::bind(&mag::mp_send_handler, this, _1));
	be->timer.expires_from_now(boost::posix_time::milliseconds(1500));
	be->timer.async_wait(_service.wrap(boost::bind(&mag::proxy_binding_retry, this, _1, pbinfo)));
}

void cmd::proxy_binding_update(proxy_binding_info& pbinfo, chrono& delay)
{
	if (pbinfo.status != ip::mproto::pba::status_ok)
		return; //error

	pbu_process(pbinfo);

	pba_sender_ptr pbas(new pba_sender(pbinfo));

	pbas->async_send(_mp_sock, boost::bind(&cmd::mp_send_handler, this, _1));

	delay.stop();
	_log(0, "PBU ", !pbinfo.lifetime ? "de-" : "", "register processing delay ", delay.get());
}

//! Changed
bcache_entry* cmd::pbu_get_bce(proxy_binding_info& pbinfo)
{
	BOOST_ASSERT((pbinfo.status == ip::mproto::pba::status_ok));

	// search for entry on BCE...if found returns it
	bcache_entry* be = _bcache.find(pbinfo.id);
	if (be)
		return be;

	//if not found, search for the router
	if (!_node_db.find_router(pbinfo.address)) {
		_log(0, "PBU registration error: MAG not authorized [id = ", pbinfo.id, ", mag = ", pbinfo.address, "]");
		pbinfo.status = ip::mproto::pba::status_not_authorized_for_proxy_reg;
		return nullptr;
	}

	//then search for the mobile node
	const mobile_node* mn = _node_db.find_mobile_node(pbinfo.id);
	if (!mn) {
		_log(0, "PBU registration error: unknown mobile node [id = ", pbinfo.id, ", mag = ", pbinfo.address, "]");
		//TODO: Change ip::mproto::pba::status_not_lma_for_this_mn to cmd
		pbinfo.status = ip::mproto::pba::status_not_lma_for_this_mn;
		return nullptr;
	}

	//check if the mobile node CDM's identifier matches
	//!Changed
	if (mn->/*lma_id()*/cmd_id() != _identifier) {
		_log(0, "PBU registration error: not this CMD [id = ", pbinfo.id, ", mag = ", pbinfo.address, "]");
		//TODO: Change ip::mproto::pba::status_not_lma_for_this_mn to cmd
		pbinfo.status = ip::mproto::pba::status_not_lma_for_this_mn;
		return nullptr;
	}

	//check if binding info is still valid (no timeout)
	if (!pbinfo.lifetime) {
		_log(0, "PBU de-registration error: binding cache entry not found [id = ", pbinfo.id, ", mag = ", pbinfo.address, "]");
		return nullptr; //note: no error for this
	}

	//update BCE with a new entry
	be = new bcache_entry(_service.get_io_service(), pbinfo.id, mn->prefix_list());
	_bcache.insert(be);

	// done
	return be;
}

bool cmd::pbu_maar_checkin(bcache_entry& be, proxy_binding_info& pbinfo)
{
	BOOST_ASSERT((pbinfo.status == ip::mproto::pba::status_ok));

	if (be.care_of_address != pbinfo.address) {
		if((pbinfo.handoff == ip::mproto::option::handoff::k_not_changed)) {
			pbinfo.status = ip::mproto::pba::status_not_authorized_for_proxy_reg;
			return false;
		}

		//!Changed: change mag to maar
		const router_node* maar = _node_db.find_router(pbinfo.address);
		if (!maar) {
			_log(0, "PBU error: unknown MAAR [id = ", pbinfo.id, ", maar = ", pbinfo.address, "]");
			pbinfo.status = ip::mproto::pba::status_not_authorized_for_proxy_reg;
			return false;
		}
		if (!pbinfo.lifetime) {
			_log(0, "PBU de-registration error: not this MAAR [id = ", pbinfo.id, ", maar = ", pbinfo.address, "]");
			return false; //note: no error for this
		}

		if (!be.care_of_address.is_unspecified())
			del_route_entries(&be);
		be.care_of_address = pbinfo.address;
		be.lifetime = pbinfo.lifetime;
		be.sequence = pbinfo.sequence;
		be.link_type = pbinfo.link_type;
		be.bind_status = bcache_entry::k_bind_unknown;

	} else {
		if (!validate_sequence_number(be.sequence, pbinfo.sequence)) {
			_log(0, "PBU error: sequence not valid [id = ", pbinfo.id,
			                                     ", maar = ", pbinfo.address,
			                                     ", sequence = ", be.sequence, " <> ", pbinfo.sequence, "]");
			pbinfo.status = ip::mproto::pba::status_bad_sequence;
			pbinfo.sequence = be.sequence;
			return false;
		}

		be.lifetime = pbinfo.lifetime;
		be.sequence = pbinfo.sequence;
	}

	return true;
}

void cmd::pbu_process(proxy_binding_info& pbinfo)
{
	bcache_entry* be = pbu_get_be(pbinfo);
	if (!be)
		return;

	//!Changed pbu_mag_checkin -> pbu_maar_checkin
	if (!pbu_maar_checkin(*be, pbinfo))
		return;

	if (pbinfo.lifetime) {
		if (be->care_of_address == pbinfo.address)
			if (be->bind_status == bcache_entry::k_bind_registered)
				_log(0, "PBU re-registration [id = ", pbinfo.id, ", maar = ", pbinfo.address, "]");
			else
				_log(0, "PBU registration [id = ", pbinfo.id, ", maar = ", pbinfo.address, "]");
		else
			_log(0, "PBU handoff [id = ", pbinfo.id, ", maar = ", pbinfo.address, "]");

		be->timer.cancel();
		be->bind_status = bcache_entry::k_bind_registered;
		add_route_entries(be);

		be->timer.expires_from_now(boost::posix_time::seconds(pbinfo.lifetime));
		be->timer.async_wait(_service.wrap(boost::bind(&cmd::expired_entry, this, _1, be->id())));
	}

	BOOST_ASSERT((be->bind_status != bcache_entry::k_bind_unknown));

	if (!pbinfo.lifetime && be->bind_status == bcache_entry::k_bind_registered) {
		_log(0, "PBU de-registration [id = ", pbinfo.id, ", maar = ", pbinfo.address, "]");

		be->timer.cancel();
		be->bind_status = bcache_entry::k_bind_deregistered;
		del_route_entries(be);
		be->care_of_address = ip::address_v6();

		be->timer.expires_from_now(boost::posix_time::milliseconds(_config.min_delay_before_BCE_delete));
		be->timer.async_wait(_service.wrap(boost::bind(&cmd::remove_entry, this, _1, be->id())));
	}
}

void cmd::expired_entry(const boost::system::error_code& ec, const std::string& mn_id)
{
	if (ec) {
		if (ec != boost::system::errc::make_error_condition(boost::system::errc::operation_canceled))
			_log(0, "Binding cache expired entry timer error: ", ec.message());

		return;
	}

	bcache_entry* be = _bcache.find(mn_id);
	if (!be || be->bind_status != bcache_entry::k_bind_registered) {
		_log(0, "Binding cache expired entry error: not found [id = ", mn_id, "]");
		return;
	}
	_log(0, "Binding expired entry [id = ", mn_id, "]");

	be->bind_status = bcache_entry::k_bind_deregistered;

	be->timer.expires_from_now(boost::posix_time::milliseconds(_config.min_delay_before_BCE_delete));
	be->timer.async_wait(_service.wrap(boost::bind(&cmd::remove_entry, this, _1, be->id())));
}

void cmd::remove_entry(const boost::system::error_code& ec, const std::string& mn_id)
{
	if (ec) {
		if (ec != boost::system::errc::make_error_condition(boost::system::errc::operation_canceled))
			_log(0, "Binding cache remove entry timer error: ", ec.message());

		return;
	}

	bcache_entry* be = _bcache.find(mn_id);
	if (!be || be->bind_status != bcache_entry::k_bind_deregistered) {
		_log(0, "Binding cache remove entry error: not found [id = ", mn_id, "]");
		return;
	}
	_log(0, "Binding cache remove entry [id = ", mn_id, "]");

	_bcache.remove(be);
}

void cmd::add_route_entries(bcache_entry* be)
{
	chrono delay;

	delay.start();

	const bcache::net_prefix_list& npl = be->prefix_list();
	uint tdev = _tunnels.get(be->care_of_address);

	_log(0, "Add route entries [id = ", be->id(), ", tunnel = ", tdev, ", CoA = ", be->care_of_address, "]");

	//TODO: change to foreach!?
	for (bcache::net_prefix_list::const_iterator i = npl.begin(), e = npl.end(); i != e; ++i)
		_route_table.add_by_dst(*i, tdev);

	delay.stop();
	_log(0, "Add route entries delay ", delay.get());
}

void cmd::del_route_entries(bcache_entry* be)
{
	chrono delay;

	delay.start();

	const bcache::net_prefix_list& npl = be->prefix_list();

	_log(0, "Remove route entries [id = ", be->id(), ", CoA = ", be->care_of_address, "]");

	for (bcache::net_prefix_list::const_iterator i = npl.begin(), e = npl.end(); i != e; ++i)
		_route_table.remove_by_dst(*i);

	_tunnels.del(be->care_of_address);

	delay.stop();
	_log(0, "Remove route entries delay ", delay.get());
}

///////////////////////////////////////////////////////////////////////////////
} /* namespace pmip */ } /* namespace opmip */

// EOF ////////////////////////////////////////////////////////////////////////

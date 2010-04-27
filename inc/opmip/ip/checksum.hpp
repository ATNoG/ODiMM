//=============================================================================
// Brief   : IP One's Complemente Checksum
// Authors : Bruno Santos <bsantos@av.it.pt>
// ----------------------------------------------------------------------------
// OPMIP - Open Proxy Mobile IP
//
// Copyright (C) 2010 Universidade de Aveiro
// Copyrigth (C) 2010 Instituto de Telecomunicações - Pólo de Aveiro
//
// This software is distributed under a license. The full license
// agreement can be found in the file LICENSE in this distribution.
// This software may not be copied, modified, sold or distributed
// other than expressed in the named license agreement.
//
// This software is distributed without any warranty.
//=============================================================================

#ifndef OPMIP_IP_CHECKSUM__HPP_
#define OPMIP_IP_CHECKSUM__HPP_

///////////////////////////////////////////////////////////////////////////////
#include <opmip/base.hpp>
#include <opmip/exception.hpp>

///////////////////////////////////////////////////////////////////////////////
namespace opmip { namespace ip {

///////////////////////////////////////////////////////////////////////////////
class checksum {
public:
	checksum()
		: _sum(0)
	{ }

	void update(const void* data, size_t len)
	{
		if (len % 2)
			OPMIP_THROW_EXCEPTION(exception(boost::system::errc::invalid_argument,
			                                boost::system::get_generic_category(),
			                                __func__));

		update(reinterpret_cast<const uint16*>(data), len / 2);
	}

	void update(const uint16* data, size_t len)
	{
		uint sum = _sum;

		for (size_t i = 0; i < len; ++i)
			sum += data[i];

		sum += (sum >> 16) & 0xffff;
		sum += (sum >> 16);

		BOOST_ASSERT(!((sum >> 16) & ~static_cast<uint>(0xffff)) && "BUG: unprocessed carry bits");

		_sum = static_cast<uint16>(sum);
	}

	uint16 final()
	{
		return ~_sum;
	}

private:
	uint16 _sum;
};

///////////////////////////////////////////////////////////////////////////////
} /* namespace ip */ } /* namespace opmip */

// EOF ////////////////////////////////////////////////////////////////////////
#endif /* OPMIP_IP_CHECKSUM__HPP_ */
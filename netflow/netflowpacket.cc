// -*- mode: c++; c-basic-offset: 2 -*-
//
// netflowpacket.{cc,hh} -- parses Netflow V1, V5, V7, V9, and IPFIX
// packets
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#include <click/config.h>
#include <click/glue.hh>
#include "netflowpacket.hh"
#if CLICK_USERLEVEL
# include <time.h>
#endif

String
NetflowPacket::unparse(bool verbose) const
{
  StringAccum sa;

  if (version() >= 10)
    sa << "IPFIX";
  else
    sa << "NetFlow V" << version();
  sa << " (" << srcaddr() << ") : ";
  sa << count() << " rec";
  if (verbose) {
    sa << "; up " << uptime() << " at " << unix_secs();
  }
  sa << "\n";
  return sa.take_string();
}

static String
print_hex(unsigned char x)
{
  String s = "0x";
  s += String("0123456789ABCDEF"[(x&0xF0)>>4]);
  s += String("0123456789ABCDEF"[x&0x0F]);
  return s;
}

String
NetflowPacket::unparse_record(int i, String tag, bool verbose) const
{
  StringAccum sa;
  if (tag)
    sa << tag << ": ";
  sa << "    ";
  if (prot(i) == IP_PROTO_TCP || prot(i) == IP_PROTO_UDP)
    sa << srcaddr(i) << ":" << sport(i) << " > " 
       << dstaddr(i) << ":" << dport(i);
  else
    sa << srcaddr(i) << " > " << dstaddr(i);

  sa << " (" << first(i) << ":" << last(i) << ")";
  sa << "; prot " << (int)prot(i);
  if (verbose) {
    sa << "; in " << input(i) << ", out " << output(i);
    sa << "; len " << dpkts(i) << "p (" << doctets(i) << "B)";
    sa << "; tos " << print_hex(tos(i));
    if (prot(i) == IP_PROTO_TCP)
      sa << "; flags " << print_hex(flags(i));
  }
  sa << "\n";
  return sa.take_string();
}

static String
format_gmtime(unsigned long seconds)
{
#ifdef CLICK_USERLEVEL
  time_t t = (time_t)seconds;
  char buf[100];
  size_t len = strftime(buf, sizeof(buf), "%F %T", gmtime(&t));
  return String(buf, len);
#else
  return String(seconds);
#endif
}

// NetFlow V9 and IPFIX

template<class Header, class Template_Field>
NetflowTemplatePacket<Header, Template_Field>::NetflowTemplatePacket(const Packet *p, Header *h, unsigned len, NetflowTemplateCache *template_cache)
  : NetflowPacket(p), _h(h), _template_cache(template_cache)
{
  len -= sizeof(Header);

  V9_Flowset *flowset, *next_flowset;

  for (flowset = (V9_Flowset *)&_h[1];
       len >= sizeof(*flowset) && len >= ntohs(flowset->length);
       len -= ntohs(flowset->length), flowset = next_flowset) {

    uint16_t flowset_id = ntohs(flowset->id);
    unsigned flowset_length = ntohs(flowset->length);

    if (flowset_length == 0)
      return;

    next_flowset = (V9_Flowset *)((intptr_t)flowset + flowset_length);

    // Template record flowset
    if ((version() == 9 && flowset_id == 0) ||
	(version() >= 10 && flowset_id == 2)) {
      V9_Template *templp, *next_templp;

      // Template flowsets may contain multiple templates
      for (templp = (V9_Template *)&flowset[1];
	   (intptr_t)&templp[1] <= (intptr_t)next_flowset;
	   templp = next_templp) {
	NetflowTemplate templ;
	Template_Field *field, *next_field;
	unsigned field_header_length, field_count;

	if (_template_cache) {
	  // Deal with template withdrawal
	  if (ntohs(templp->count) == 0) {
	    if (ntohs(templp->id) == 2) {
	      // Withdraw ALL templates from this source ID
	      _template_cache->remove(NetflowPacket::srcaddr(), ntohl(_h->source_id));
	    } else {
	      // Withdraw the template
	      _template_cache->remove(NetflowPacket::srcaddr(), ntohl(_h->source_id), ntohs(templp->id));
	    }
	  }
	}

	for (field = (Template_Field *)&templp[1],
	       field_count = ntohs(templp->count);
	     (intptr_t)&field->length < (intptr_t)next_flowset &&
	       field_count;
	     field = next_field,
	       field_count--) {
	  // IPFIX template fields may specify an "enterprise specific
	  // information element" by setting the top bit of the type
	  // field, in which case an enterprise number follows the
	  // length field. Otherwise, it's a Netflow V9 field (1-127)
	  // or a new IPFIX field (128-32767).
	  uint16_t field_type = ntohs(field->type);
	  uint32_t enterprise = 0;

	  // Figure out which kind of template field this is
	  if (version() == 9 || field_type < 32768)
	    field_header_length = sizeof(V9_Template_Field);
	  else
	    field_header_length = sizeof(IPFIX_Template_Field);
	  next_field = (Template_Field *)((intptr_t)field + field_header_length);

	  if ((intptr_t)next_field > (intptr_t)next_flowset)
	    break;

	  // If an enterprise specific type
	  if (version() > 9 && field_type >= 32768) {
	    field_type -= 32768;
	    enterprise = ntohl(((IPFIX_Template_Field *)field)->enterprise);
	  }

	  templ.push_back(NetflowTemplateField(enterprise, field_type, ntohs(field->length)));
	}

	if (_template_cache)
	  _template_cache->insert(NetflowPacket::srcaddr(),
				  ntohl(_h->source_id), ntohs(templp->id),
				  templ);

	next_templp = (V9_Template *)field;
      }
    }

    // Options record flowset
    else if ((version() == 9 && flowset_id == 1) ||
	     (version() >= 10 && flowset_id == 3)) {
    }

    // Reserved
    else if (flowset_id >= 2 && flowset_id <= 255) {
    }

    // Data flowset
    else if (_template_cache) {
      NetflowTemplate *templ = _template_cache->findp(NetflowPacket::srcaddr(), ntohl(_h->source_id), flowset_id);

      if (templ) {
	const uint8_t *pdu = (const uint8_t *)&flowset[1];
	// Does not include length of variable length fields (added to
	// template_length later below).
	unsigned template_length = templ->length();

	for (;
	     flowset_length >= template_length;
	     pdu += template_length,
	       flowset_length -= template_length) {
	  NetflowDataRecord record;
	  const uint8_t *field_data = pdu;

	  for (int i = 0; i < templ->size(); i++) {
	    uint32_t enterprise = templ->at(i).enterprise();
	    uint16_t field_type = templ->at(i).type();
	    unsigned field_length = templ->at(i).length();

	    // Deal with variable length information element
	    if (field_length == 65535) {
	      // Check for runt
	      if ((intptr_t)(field_data + 1) > (intptr_t)next_flowset)
		break;
	      // If length is less than 255, it is encoded in the
	      // first byte of the information element.
	      field_length = unaligned_ntoh<uint8_t>(field_data);
	      field_data++;
	      template_length++;
	      if (field_length == 255) {
		// Check for runt
		if ((intptr_t)(field_data + 2) > (intptr_t)next_flowset)
		  break;
		// If length is greater than or equal to 255, it is
		// encoded in the next two bytes.
		field_length = unaligned_ntoh<uint16_t>(field_data);
		field_data += 2;
		template_length += 2;
	      }
	      if (flowset_length < template_length)
		break;
	      assert((intptr_t)(field_data + field_length) <= (intptr_t)next_flowset);
	    }

	    record.insert(NetflowData(enterprise, field_type, field_data, field_length));
	    field_data += field_length;
	  }

	  _r.push_back(record);
	}
      }
    }
  }
}

// NetflowTemplatePacket specializations

template<> unsigned long
NetflowVersion9Packet::uptime() const
{
  return ntohl(_h->uptime);
}

template<> unsigned long
NetflowVersion9Packet::first(int i) const {
  return unix_secs() + (int)(_r[i].first() - uptime()) / 1000;
}

template<> unsigned long
NetflowVersion9Packet::last(int i) const {
  return unix_secs() + (int)(_r[i].last() - uptime()) / 1000;
}

template<> Timestamp 
NetflowVersion9Packet::first_ts(int i) const {
  return Timestamp(unix_secs() + (int)(_r[i].first() - uptime()) / 1000,
                   unix_nsecs());
}

template<> Timestamp 
NetflowVersion9Packet::last_ts(int i) const {
  return Timestamp(unix_secs() + (int)(_r[i].last() - uptime()) / 1000,
            unix_nsecs());
}

// IPFIX header has no uptime field. Uptime of the device can be
// obtained from the sysUpTime field in an option flowset, but option
// records are not currently parsed.
template <>
unsigned long
NetflowTemplatePacket<NetflowPacket::IPFIX_Header,
		      NetflowPacket::IPFIX_Template_Field>::uptime() const
{
  return 0;
}

template <>
unsigned long
NetflowTemplatePacket<NetflowPacket::IPFIX_Header,
		      NetflowPacket::IPFIX_Template_Field>::first(int i) const {
  return _r[i].value<unsigned long>(0, IPFIX_flowStartSeconds);
}

template <>
unsigned long
NetflowTemplatePacket<NetflowPacket::IPFIX_Header,
		      NetflowPacket::IPFIX_Template_Field>::last(int i) const {
  return _r[i].value<unsigned long>(0, IPFIX_flowEndSeconds);
}

template <>
Timestamp
NetflowTemplatePacket<NetflowPacket::IPFIX_Header,
                      NetflowPacket::IPFIX_Template_Field>::first_ts(int i) const
{
  return Timestamp(_r[i].value<unsigned long>(0, IPFIX_flowStartSeconds),
                   unix_nsecs());
}

template <>
Timestamp
NetflowTemplatePacket<NetflowPacket::IPFIX_Header,
                      NetflowPacket::IPFIX_Template_Field>::last_ts(int i) const
{
  return Timestamp(_r[i].value<unsigned long>(0, IPFIX_flowEndSeconds),
                   unix_nsecs());
}

template<class Header, class Template_Field> String
NetflowTemplatePacket<Header, Template_Field>::unparse_record(int i, String tag, bool verbose) const
{
  StringAccum sa;
  if (tag)
    sa << tag << ": ";
  sa << "    ";

  const NetflowData *src, *dst, *sport, *dport;
  src = _r[i].findp(0, IPFIX_sourceIPv4Address);
  dst = _r[i].findp(0, IPFIX_destinationIPv4Address);
  sport = _r[i].findp(0, IPFIX_sourceTransportPort);
  dport = _r[i].findp(0, IPFIX_destinationTransportPort);
  if (src)
    sa << src->str();
  if (sport)
    sa << ":" << sport->str();
  if (src || dst)
    sa << " > ";
  if (dst)
    sa << dst->str();
  if (dport)
    sa << ":" << dport->str();

  const NetflowData *first, *last;
  first = _r[i].findp(0, IPFIX_flowStartSysUpTime);
  last = _r[i].findp(0, IPFIX_flowEndSysUpTime);
  if ((first && first->parsed()) || (last && last->parsed())) {
    sa << " (";
    if (first && first->parsed()) {
      sa << format_gmtime(this->first(i));
      if (last && last->parsed())
	sa << ":";
    }
    if (last && last->parsed())
      sa << format_gmtime(this->last(i));
    sa << ")";
  }

  const NetflowData *prot;
  prot = _r[i].findp(0, IPFIX_protocolIdentifier);
  if (prot)
    sa << "; prot " << prot->str();

  if (verbose) {
    const NetflowData *input, *output;
    input = _r[i].findp(0, IPFIX_ingressInterface);
    output = _r[i].findp(0, IPFIX_egressInterface);

    const NetflowData *in_src_mac, *in_dst_mac, *out_src_mac, *out_dst_mac;
    in_src_mac = _r[i].findp(0, IPFIX_sourceMacAddress);
    in_dst_mac = _r[i].findp(0, IPFIX_destinationMacAddress);
    out_src_mac = _r[i].findp(0, IPFIX_postSourceMacAddress);
    out_dst_mac = _r[i].findp(0, IPFIX_postDestinationMacAddr);

    if (input || output ||
	in_src_mac || in_dst_mac || out_src_mac || out_dst_mac) {
      sa << "; ";
      if (input || in_src_mac || in_dst_mac) {
	sa << "in";
	if (input)
	  sa << " " << input->str();
	if (in_src_mac || in_dst_mac) {
	  sa << " (";
	  if (in_src_mac)
	    sa << in_src_mac->str();
	  if (in_src_mac || in_dst_mac)
	    sa << " > ";
	  if (in_dst_mac)
	    sa << in_dst_mac->str();
	  sa << ")";
	}
	if (output)
	  sa << ", ";
      }
      if (output || out_src_mac || out_dst_mac) {
	sa << "out";
	if (output)
	  sa << " " << output->str();
	if (out_src_mac || out_dst_mac) {
	  sa << " (";
	  if (out_src_mac)
	    sa << out_src_mac->str();
	  if (out_src_mac || out_dst_mac)
	    sa << " > ";
	  if (out_dst_mac)
	    sa << out_dst_mac->str();
	  sa << ")";
	}
      }
    }

    const NetflowData *dpkts, *doctets;
    dpkts = _r[i].findp(0, IPFIX_packetDeltaCount);
    doctets = _r[i].findp(0, IPFIX_octetDeltaCount);
    if (dpkts || doctets) {
      sa << "; len ";
      if (dpkts) {
	sa << dpkts->str() << "p";
	if (doctets)
	  sa << " (";
      }
      if (doctets) {
	sa << doctets->str() << "B";
	if (dpkts)
	  sa << ")";
      }
    }

    const NetflowData *tos;
    tos = _r[i].findp(0, IPFIX_classOfServiceIPv4);
    if (tos && tos->parsed())
      sa << "; tos " << print_hex(_r[i].tos());

    const NetflowData *flags;
    flags = _r[i].findp(0, IPFIX_tcpControlBits);
    if (flags && flags->parsed())
      sa << "; flags " << print_hex(_r[i].flags());

    // Print a list of the fields
    for (NetflowDataIterator iter = _r[i].begin(); iter.live(); iter++) {
      NetflowData data = iter.value();
      sa << "; " << ipfix_name(data.type()) << " " << data.str();
    }
  }

  sa << "\n";

  return sa.take_string();
}

// Instantiations

// Data flowset is a vector of data records

// NetflowVersion9Packet
template class NetflowTemplatePacket<NetflowPacket::V9_Header, NetflowPacket::V9_Template_Field>;

// IPFIXPacket
template class NetflowTemplatePacket<NetflowPacket::IPFIX_Header, NetflowPacket::IPFIX_Template_Field>;

ELEMENT_PROVIDES(NetflowPacket)

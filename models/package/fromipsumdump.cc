/*
 * fromipsumdump.{cc,hh} -- element reads packets from IP summary dump file
 * Eddie Kohler
 *
 * Copyright (c) 2001 International Computer Science Institute
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>

#include "fromipsumdump.hh"
#include "toipsumdump.hh"
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/click_ip.h>
#include <click/click_udp.h>
#include <click/click_tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

FromIPSummaryDump::FromIPSummaryDump()
    : Element(0, 1), _fd(-1), _pos(0), _len(0), _task(this)
{
    MOD_INC_USE_COUNT;
}

FromIPSummaryDump::~FromIPSummaryDump()
{
    MOD_DEC_USE_COUNT;
    uninitialize();
}

int
FromIPSummaryDump::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    bool stop = false, active = true, zero = false;
    uint8_t default_proto = IP_PROTO_TCP;
    _sampling_prob = (1 << SAMPLING_SHIFT);
    
    if (cp_va_parse(conf, this, errh,
		    cpFilename, "dump file name", &_filename,
		    cpKeywords,
		    "STOP", cpBool, "stop driver when done?", &stop,
		    "ACTIVE", cpBool, "start active?", &active,
		    "ZERO", cpBool, "zero packet data?", &zero,
		    "SAMPLE", cpUnsignedReal2, "sampling probability", SAMPLING_SHIFT, &_sampling_prob,
		    "PROTO", cpByte, "default IP protocol", &default_proto,
		    0) < 0)
	return -1;
    if (_sampling_prob > (1 << SAMPLING_SHIFT)) {
	errh->warning("SAMPLE probability reduced to 1");
	_sampling_prob = (1 << SAMPLING_SHIFT);
    } else if (_sampling_prob == 0)
	errh->warning("SAMPLE probability is 0; emitting no packets");

    _default_proto = default_proto;
    _stop = stop;
    _active = active;
    _zero = zero;
    return 0;
}

int
FromIPSummaryDump::error_helper(ErrorHandler *errh, const char *x)
{
    if (errh)
	errh->error("%s: %s", _filename.cc(), x);
    else
	click_chatter("%s: %s", declaration().cc(), x);
    return -1;
}

int
FromIPSummaryDump::read_buffer(ErrorHandler *errh)
{
    if (_pos == 0 && _len == _buffer.length())
	_buffer.append_garbage(BUFFER_SIZE);

    unsigned char *data = (unsigned char *)_buffer.mutable_data();
    int buffer_len = _buffer.length();

    if (_len == buffer_len) {
	memmove(data, data + _pos, _len - _pos);
	_len -= _pos;
	_pos = 0;
    }
    int initial_len = _len;
    
    while (_len < buffer_len) {
	ssize_t got = read(_fd, data + _len, buffer_len - _len);
	if (got > 0)
	    _len += got;
	else if (got == 0)	// premature end of file
	    return _len - initial_len;
	else if (got < 0 && errno != EINTR && errno != EAGAIN)
	    return error_helper(errh, strerror(errno));
    }
    
    return _len - initial_len;
}

int
FromIPSummaryDump::read_line(String &result, ErrorHandler *errh)
{
    int epos = _pos;

    while (1) {
	bool done = false;
	
	if (epos >= _len) {
	    int delta = epos - _pos;
	    int errcode = read_buffer(errh);
	    if (errcode < 0 || (errcode == 0 && delta == 0))	// error
		return errcode;
	    else if (errcode == 0)
		done = true;
	    epos = _pos + delta;
	}

	const char *d = _buffer.data();
	while (epos < _len && d[epos] != '\n' && d[epos] != '\r')
	    epos++;

	if (epos < _len || done) {
	    result = _buffer.substring(_pos, epos - _pos);
	    if (epos < _len && d[epos] == '\r')
		epos++;
	    if (epos < _len && d[epos] == '\n')
		epos++;
	    _pos = epos;
	    return 1;
	}
    }
}

int
FromIPSummaryDump::initialize(ErrorHandler *errh)
{
    if (_filename == "-") {
	_fd = STDIN_FILENO;
	_filename = "<stdin>";
    } else
	_fd = open(_filename.cc(), O_RDONLY);
    if (_fd < 0)
	return errh->error("%s: %s", _filename.cc(), strerror(errno));

    _pos = _len = 0;
    _buffer = String();
    int result = read_buffer(errh);
    if (result < 0) {
	uninitialize();
	return -1;
    } else if (result == 0) {
	uninitialize();
	return errh->error("%s: empty file", _filename.cc());
    }

    String line;
    if (read_line(line, errh) < 0) {
	uninitialize();
	return -1;
    } else if (line.substring(0, 14) != "!IPSummaryDump") {
	errh->warning("%s: missing banner line; is this an IP summary dump?");
	_pos = 0;
    }
    
    _format_complaint = false;
    if (output_is_push(0))
	ScheduleInfo::initialize_task(this, &_task, _active, errh);
    return 0;
}

void
FromIPSummaryDump::uninitialize()
{
    if (_fd >= 0 && _fd != STDIN_FILENO)
	close(_fd);
    _fd = -1;
    _buffer = String();
    _task.unschedule();
}

void
FromIPSummaryDump::bang_data(const String &line, ErrorHandler *errh)
{
    Vector<String> words;
    cp_spacevec(line, words);

    _contents.clear();
    for (int i = 1; i < words.size(); i++) {
	String word = cp_unquote(words[i]);
	int what = ToIPSummaryDump::parse_content(word);
	if (what > W_NONE && what < W_LAST)
	    _contents.push_back(what);
	else
	    error_helper(errh, "unknown content type `" + word + "'");
    }

    if (_contents.size() == 0)
	error_helper(errh, "no contents specified");
}

Packet *
FromIPSummaryDump::read_packet(ErrorHandler *errh)
{
    WritablePacket *q = Packet::make((const char *)0, sizeof(click_ip) + sizeof(click_tcp));
    if (!q) {
	error_helper(errh, "out of memory!");
	return 0;
    }
    if (_zero)
	memset(q->data(), 0, q->length());
    q->set_ip_header((click_ip *)q->data(), sizeof(click_ip));
    click_ip *iph = q->ip_header();
    iph->ip_v = 4;
    iph->ip_hl = sizeof(click_ip) >> 2;
    iph->ip_p = _default_proto;
    
    String line;
    Vector<String> words;
    int j;
    
    while (1) {

	if (read_line(line, errh) <= 0) {
	    q->kill();
	    return 0;
	}

	const char *data = line.data();
	int len = line.length();

	if (len >= 6 && memcmp(data, "!data", 5) == 0 && isspace(data[5])) {
	    bang_data(line, errh);
	    continue;
	} else if (len >= 7 && memcmp(data, "!proto", 6) == 0 && isspace(data[6])) {
	    //handle_proto_line(line, errh);
	    continue;
	} else if (len == 0 || data[0] == '!' || data[0] == '#')
	    continue;

	words.clear();
	cp_spacevec(line, words);
	if (words.size() != _contents.size() || _contents.size() == 0)
	    break;		// bad format

	// checking sampling probability
	if (_sampling_prob < (1 << SAMPLING_SHIFT)
	    && (uint32_t)(random() & ((1 << SAMPLING_SHIFT) - 1)) >= _sampling_prob)
	    continue;
    
	bool ok = true;
	for (int i = 0; i < _contents.size() && ok; i++)
	    switch (_contents[i]) {

	      case W_TIMESTAMP:
		ok = cp_timeval(words[i], &q->timestamp_anno());
		break;

	      case W_TIMESTAMP_SEC:
		ok = cp_integer(words[i], (int32_t *)&q->timestamp_anno().tv_sec);
		break;

	      case W_TIMESTAMP_USEC:
		ok = cp_integer(words[i], (int32_t *)&q->timestamp_anno().tv_usec);
		break;
		
	      case W_SRC:
		ok = cp_ip_address(words[i], (unsigned char *)&iph->ip_src);
		break;

	      case W_DST:
		ok = cp_ip_address(words[i], (unsigned char *)&iph->ip_dst);
		break;
		
	      case W_LENGTH:
		ok = (cp_integer(words[i], &j) && j >= 0 && j <= 0xFFFF);
		iph->ip_len = htons(j);
		break;
		
	      case W_PROTO:
		ok = (cp_integer(words[i], &j) && j >= 0 && j <= 255);
		iph->ip_p = j;
		break;

	      case W_IPID:
		ok = (cp_integer(words[i], &j) && j >= 0 && j <= 0xFFFF);
		iph->ip_id = htons(j);
		break;

	      case W_SPORT: {
		  ok = (cp_integer(words[i], &j) && j >= 0 && j <= 0xFFFF);
		  click_udp *udph = (click_udp *)q->transport_header();
		  udph->uh_sport = htons(j);
		  break;
	      }

	      case W_DPORT: {
		  ok = (cp_integer(words[i], &j) && j >= 0 && j <= 0xFFFF);
		  click_udp *udph = (click_udp *)q->transport_header();
		  udph->uh_dport = htons(j);
		  break;
	      }

	      default:
		ok = false;
		break;

	    }

	if (!ok)
	    break;
	return q;
    }

    // bad format if we get here
    if (!_format_complaint) {
	error_helper(errh, "bad format");
	_format_complaint = true;
    }
    if (q)
	q->kill();
    return 0;
}

void
FromIPSummaryDump::run_scheduled()
{
    if (!_active)
	return;

    Packet *p = read_packet(0);
    if (!p) {
	if (_stop)
	    router()->please_stop_driver();
	return;
    }
    
    output(0).push(p);
    _task.fast_reschedule();
}

Packet *
FromIPSummaryDump::pull(int)
{
    if (!_active)
	return 0;

    Packet *p = read_packet(0);
    if (!p && _stop)
	router()->please_stop_driver();
    return p;
}

String
FromIPSummaryDump::read_handler(Element *e, void *thunk)
{
    FromIPSummaryDump *fd = static_cast<FromIPSummaryDump *>(e);
    switch ((int)thunk) {
      case 0:
	return cp_unparse_real2(fd->_sampling_prob, SAMPLING_SHIFT) + "\n";
      case 1:
	return cp_unparse_bool(fd->_active) + "\n";
      default:
	return "<error>\n";
    }
}

int
FromIPSummaryDump::write_handler(const String &s_in, Element *e, void *thunk, ErrorHandler *errh)
{
    FromIPSummaryDump *fd = static_cast<FromIPSummaryDump *>(e);
    String s = cp_uncomment(s_in);
    switch ((int)thunk) {
      case 1: {
	  bool active;
	  if (cp_bool(s, &active)) {
	      fd->_active = active;
	      if (active && fd->output_is_push(0) && !fd->_task.scheduled())
		  fd->_task.reschedule();
	      return 0;
	  } else
	      return errh->error("`active' should be Boolean");
      }
      default:
	return -EINVAL;
    }
}

void
FromIPSummaryDump::add_handlers()
{
    add_read_handler("sampling_prob", read_handler, (void *)0);
    add_read_handler("active", read_handler, (void *)1);
    add_write_handler("active", write_handler, (void *)1);
    if (output_is_push(0))
	add_task_handlers(&_task);
}

ELEMENT_REQUIRES(userlevel ToIPSummaryDump)
EXPORT_ELEMENT(FromIPSummaryDump)

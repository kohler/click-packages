/*
 * splitfirst.{cc,hh} -- element splits the first N packets 
 * to output port 1, to port 0 othrwise.
 *
 * Example of usage in a Click configuration:
 * elementclass class_stat {
 *       $first, $av_length, $av_rate, $dscp |
 *       split::SplitFirst($first);
 *       check_length::CheckAverageLength($av_length);
 *       check_rate::Meter($av_rate);
 *       set::SetIPDSCP($dscp);
 *       input->split;
 *       split[1]->[1]output;
 *       split[0]->check_length;
 *       check_length[0]->[2]output;
 *       check_length[1]->check_rate;
 *       check_rate[0]->[3]output;
 *       check_rate[1]->set->[0]output;
 *       }
 *
 *
 * Giorgio Calarco, Carla Raffaelli
 *
 * Copyright (c) 2003 DEIS - Dept.of Electronics, Computer Science and Systems
 * University of Bologna
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
#include "splitfirst.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/confparse.hh>

SplitFirst::SplitFirst()
{
}

SplitFirst::~SplitFirst()
{
}

int
SplitFirst::configure(Vector<String> &conf, ErrorHandler *errh)
{
  current_no_of_packets = 0;
  if (cp_va_kparse(conf, this, errh, 
		   "THRESHOLD", cpkP+cpkM, cpUnsigned, &threshold, cpEnd) < 0) 
    return -1;
  return 0;
}

void
SplitFirst::push(int, Packet *p)
{
  current_no_of_packets = current_no_of_packets + 1 ;
  if (current_no_of_packets>threshold) output(0).push(p);
     else  output(1).push(p);
}


EXPORT_ELEMENT(SplitFirst)
ELEMENT_REQUIRES(linuxmodule)

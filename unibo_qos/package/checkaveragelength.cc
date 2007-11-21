/*
 * checkaveragelength.{cc,hh} -- element splits packets depending on 
 * the average length of the last ELM packets received. 
 * If the average lenght is less than the value of min (this a configurable 
 * parameter using an handler), packets get out from port 1, 
 * from port 0 otherwise. 
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
#include "checkaveragelength.hh"
#include <click/confparse.hh>
#include <click/error.hh>

CheckAverageLength::CheckAverageLength()
{
}


CheckAverageLength::~CheckAverageLength()
{
}

void
CheckAverageLength::media() {
   int x;
   cont = 0;
   for(x=0 ; x<ELM ; x++) {
         a[x] = 0;
	 cont = 0;
      }
}


int
CheckAverageLength::configure(Vector<String> &conf, ErrorHandler *errh)
{
   media();
   return cp_va_kparse(conf, this, errh,
		       "MINLENGTH", cpkP+cpkM, cpUnsigned, &min,
		       cpEnd);
}


void
CheckAverageLength::ins(unsigned dato) {
   int x;
   for(x=(ELM-1); x>0; x--) {
      a[x] = a[x-1];
      }
   a[0] = dato;
}


unsigned
CheckAverageLength::average() {
   int i;
   unsigned sum;
   cont = cont + 1;
   sum = 0;
   for(i=0; i<ELM; i++) { 
      sum = sum + a[i];
      }
   if (cont<ELM) return (sum / cont);
      else return (sum / ELM);
}
	 
	 


void
CheckAverageLength::push(int, Packet *p)
{
  unsigned length;
  length = p->length();
  ins(length);
  av_length = average();
  if (av_length < min) output(1).push(p);
     else output(0).push(p);
}


EXPORT_ELEMENT(CheckAverageLength)
ELEMENT_MT_SAFE(CheckAverageLength)
ELEMENT_REQUIRES(linuxmodule)

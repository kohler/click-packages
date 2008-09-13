/*
 * rtpclassifier.{cc,hh} -- element classifies RTP flows from BE traffic
 * Flows are classified as RTP flow if 6 following packets contain the
 * same SSRC field. These packets are to be received before TIMEOUT seconds.
 * If not, flow informations are cancelled. RTP packets get out from port 0,
 * others from port 1.
 * RTPClassifier[0]-> RTP traffic
 * RTPClassifier[1]-> non-RTP traffic
 *
 * Example of usage in Click Configuration:
 *
 * elementclass class_RTP {
 *    $ssrc, $dscp |
 *    get::GetSSRC($ssrc);
 *    rtp::RTPClassifier;
 *    set::SetIPDSCP($dscp);
 *    input->get[0]->rtp;
 *    get[1]->[1]output;
 *    rtp[0]->set->[0]output;
 *    rtp[1]->[1]output;
 *    }
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
#include "rtpclassifier.hh"
#include "packet_anno.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/packet_anno.hh>

RTPClassifier::RTPClassifier()
{
  FlowTable();
}


RTPClassifier::~RTPClassifier()
{
}

void
RTPClassifier::FlowTable() {
   int x,y;
   for(x=0 ; x<MAX ; x++) {
      for(y=0 ; y<COL ; y++) {
         table[x][y] = 0;
         }
      }
   for(x=0 ; x<NRTP ; x++) {
      for(y=0 ; y<COL ; y++) {
         tabrtp[x][y] = 0;
         }
      }   
}


void
RTPClassifier::del_old_flow(unsigned now) {
   unsigned nf,x,flag,old,diff;
   for(x=0; x<MAX ; x++) { 
      flag = table[x][2];
      if (flag!=0) {
         old = table[x][1];
	 diff = now - old;
	 if (diff>TIMEOUT) table[x][2] = 0;    
         }
      }
   for(x=0; x<NRTP ; x++) { 
      flag = tabrtp[x][2];
      if (flag!=0) {
         old = tabrtp[x][1];
	 diff = now - old;
	 if (diff>TIMEOUTRTP) tabrtp[x][2] = 0;    
         }
      }
}


bool
RTPClassifier::is_rtp(unsigned x) {
   unsigned rtp,flag;
   flag = tabrtp[x][2];
   rtp = tabrtp[x][3];
   if (flag==1) { if (rtp==1) return true;
                  else return false; }
      else return false;
}



unsigned
RTPClassifier::ins_flow_rtp(unsigned ssrc, unsigned time) {
   unsigned x,flag;
   for(x=0; x<NRTP ; x++) {
      flag = tabrtp[x][2];
      if (flag==0) {
         tabrtp[x][0] = ssrc;
	 tabrtp[x][1] = time;
	 tabrtp[x][2] = 1;
	 tabrtp[x][3] = 1;
	 tabrtp[x][4] = 7;
	 return x;
	 }
   }
   return ERROR; // if here, we have reached the max number of flows per SLA
}


unsigned
RTPClassifier::ins_flow(unsigned ssrc, unsigned time) {
   unsigned x,flag,y;
   for(x=0; x<NRTP ; x++) {
      flag = tabrtp[x][2];
      if (flag!=0) {
         if (tabrtp[x][0]==ssrc) {
	    tabrtp[x][1] = time;
	    return x;
	    }
	 }
     }   
   for(x=0; x<MAX ; x++) {
      flag = table[x][2];
      if (flag!=0) {
         if (table[x][0]==ssrc) {
	    if (table[x][4]<=6) table[x][4] = table[x][4] + 1;
	    table[x][1] = time;
		if (table[x][4]>6) { // checks if the sixth packet is received
	           y = ins_flow_rtp(ssrc,time);
	           return y;
 	           }
	    return NORTP;
	    }
         }
      }     
   for(x=0; x<MAX ; x++) {
      flag = table[x][2];
      if (flag==0) {
         table[x][0] = ssrc;
	 table[x][1] = time;
	 table[x][2] = 1;
	 table[x][3] = 0;
	 table[x][4] = 1;
	 return NORTP;
	 }
   }


// This code should not usually be reached, if so the table is full !
   return ERROR;
}

    
void 
RTPClassifier::push(int, Packet *p)
{  
    unsigned ssrc,nf,sec;
    Timestamp now = Timestamp::now();
    sec = now.sec();
    ssrc = SSRC_ANNO(p); 
    del_old_flow(sec);
    nf = ins_flow(ssrc,sec);
    if (nf==NORTP) nf = ERROR;
    if (nf==ERROR) output(1).push(p);
       else {    
             if (is_rtp(nf)) { 
                SET_AGGREGATE_ANNO(p,nf); 
	        output(0).push(p); }
             else { output(1).push(p); }
	     }
    return;      
}


// HANDLERS

void
RTPClassifier::add_handlers()
{
 
}

EXPORT_ELEMENT(RTPClassifier)
ELEMENT_REQUIRES(linuxmodule)

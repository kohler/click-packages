% Copyright (c) 2005 University of Bristol
%
% Permission is hereby granted, free of charge, to any person obtaining a
% copy of this software and associated documentation files (the "Software"),
% to deal in the Software without restriction, subject to the conditions
% listed in the Click LICENSE file. These conditions include: you must
% preserve this copyright notice, and you cannot mention the copyright
% holders in advertising related to the Software without their permission.
% The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
% notice is a summary of the Click LICENSE file; the license in that file is
% legally binding.

input elements;
verbatimtex %&latex
\documentclass[12pt]{article}
\usepackage{elemfig}
\begin{document}
etex;
picture emptyqueue; emptyqueue := btex \phantom{\elementlabel{Queue}} etex;
picture vemptyqueue; vemptyqueue := emptyqueue rotated 90 xscaled .4;

%% 1
%% IPv4 multicast router
beginfig(1);

  velementit.src.A(btex \element{FromDevice(eth0)} etex, 0, 1, push);
  velementit.classifier.A(btex \element{~~~~~~~~~~~~Classif{}ier(...)~~~~~~~~~~~~}\lower3.8ex\null etex, 1, 4, agnostic_push);
  velementit.discard.A(btex \element{Discard} etex, 1, 0, push);

  classifier.A.in[0] - src.A.out[0] = (0,-40);
  discard.A.in[0]-classifier.A.out[3] = (25,-15);

  velementit.src.B(btex \element{FromDevice(eth1)} etex, 0, 1, push);
  velementit.classifier.B(btex \element{~~~~~~~~~~~~Classif{}ier(...)~~~~~~~~~~~~}\lower3.8ex\null etex, 1, 4, agnostic_push);
  velementit.discard.B(btex \element{Discard} etex, 1, 0, push);

  classifier.B.in[0] - src.B.out[0] = (0,-10);
  discard.B.in[0]-classifier.B.out[3] = (10,-15);
  
  velementit.src.C(btex \element{FromDevice(eth2)} etex, 0, 1, push);
  velementit.classifier.C(btex \element{~~~~~~~~~~~~Classif{}ier(...)~~~~~~~~~~~~}\lower3.8ex\null etex, 1, 4, agnostic_push);
  velementit.discard.C(btex \element{Discard} etex, 1, 0, push);

  classifier.C.in[0] - src.C.out[0] = (0,-40);
  discard.C.in[0]-classifier.C.out[0] = (-25,-15);

  src.C.w - src.B.e = (90,0);
  src.B.w - src.A.e = (90,0);	  

  drawelement(src.A,src.B,src.C,classifier.A,classifier.B,classifier.C,discard.A,discard.B,discard.C);
  
  drawconnect(src.A,0,0,classifier.A);
  drawconnect(src.B,0,0,classifier.B);
  drawconnect(src.C,0,0,classifier.C);

  drawconnect(classifier.A,3,0,discard.A);
  drawconnect(classifier.B,3,0,discard.B);
  drawconnect(classifier.C,0,0,discard.C);
 
  velementit.paint.A(btex \element{Paint(0)} etex, 1, 1, push);
  velementit.paint.B(btex \element{Paint(1)} etex, 1, 1, push);
  velementit.paint.C(btex \element{Paint(2)} etex, 1, 1, push);

  velementit.strip.A(btex \element{Strip(14)} etex, 1, 1, push);
  velementit.strip.B(btex \element{Strip(14)} etex, 1, 1, push);
  velementit.strip.C(btex \element{Strip(14)} etex, 1, 1, push);


  strip.A.in[0]-classifier.A.out[2] = (35, -100);
  strip.B.in[0]-classifier.B.out[2] = (25, -105);
  strip.C.in[0]-classifier.C.out[1] = (-35, -100);



  strip.A.in[0]-paint.A.out[0] = (0, -20);
  strip.B.in[0]-paint.B.out[0] = (0, -20);
  strip.C.in[0]-paint.C.out[0] = (0, -20);


  velementit.arpr.A(btex \melementlabel{ARPResponder\\(...)} etex scaled 0.7, 1, 1, agnostic_push);
  velementit.arpr.B(btex \melementlabel{ARPResponder\\(...)} etex scaled 0.7, 1, 1, agnostic_push);
  velementit.arpr.C(btex \melementlabel{ARPResponder\\(...)} etex scaled 0.7, 1, 1, agnostic_push);
  classifier.A.out[1] - arpr.A.in[0] = (0,40);
  classifier.B.out[1] - arpr.B.in[0] = (10,25);
  classifier.C.out[2] - arpr.C.in[0] = (0,40);

  drawelement(paint.A, paint.B, paint.C, strip.A, strip.B, strip.C, arpr.A, arpr.B, arpr.C);

%  dy = ypart arpr.A.out[0] - 5 - ypart classifier.A.out[1];
  drawarrow classifier.A.out[0]{down} .. classifier.A.out[0] + (0,-10) withpen connectionpen;
  label.bot(btex ~to \element{ARPQuerier} etex scaled 0.8, classifier.A.out[0] + (-5,-10));

  drawarrow classifier.B.out[0]{down} .. classifier.B.out[0] + (0,-10) withpen connectionpen;
  label.bot(btex ~to \element{ARPQuerier} etex scaled 0.8, classifier.B.out[0] + (-8,-10));

  drawarrow classifier.C.out[3]{down} .. classifier.C.out[3] + (0,-10) withpen connectionpen;
  label.bot(btex ~to \element{ARPQuerier} etex scaled 0.8, classifier.C.out[3] + (+5,-10));

  drawarrow arpr.A.out[0]{down} .. arpr.A.out[0] + (0,-10) withpen connectionpen;
  label.bot(btex ~to \element{ARPQuerier} etex scaled 0.8, arpr.A.out[0] + (-5,-10));

  drawarrow arpr.B.out[0]{down} .. arpr.B.out[0] + (0,-10) withpen connectionpen;
  label.bot(btex ~to \element{ARPQuerier} etex scaled 0.8, arpr.B.out[0] + (-5,-10));

  drawarrow arpr.C.out[0]{down} .. arpr.C.out[0] + (0,-10) withpen connectionpen;
  label.bot(btex ~to \element{ARPQuerier} etex scaled 0.8, arpr.C.out[0] + (-5,-10));

  drawconnect(classifier.A,2,0,paint.A);
  drawconnect(classifier.B,2,0,paint.B);
  drawconnect(classifier.C,1,0,paint.C);

  drawconnect(paint.A,0,0,strip.A);
  drawconnect(paint.B,0,0,strip.B);
  drawconnect(paint.C,0,0,strip.C);

  drawconnect(classifier.A,1,0,arpr.A);
  drawconnect(classifier.B,1,0,arpr.B);
  drawconnect(classifier.C,2,0,arpr.C);

  velementit.checkipheader.A(btex \element{CheckIPHeader(...)} etex, 1, 1, push);
  velementit.checkipheader.B(btex \element{CheckIPHeader(...)} etex, 1, 1, push);
  velementit.checkipheader.C(btex \element{CheckIPHeader(...)} etex, 1, 1, push);

  velementit.pim.A(btex \element{PIM} etex, 1, 1, push);
  velementit.pim.B(btex \element{PIM} etex, 1, 1, push);
  velementit.pim.C(btex \element{PIM} etex, 1, 1, push);

  strip.A.out[0] - checkipheader.A.in[0] = (0,20);
  strip.B.out[0] - checkipheader.B.in[0] = (0,20);
  strip.C.out[0] - checkipheader.C.in[0] = (0,20);

  checkipheader.A.in[0] - pim.A.out[0]= (0,60);
  checkipheader.B.in[0] - pim.B.out[0]= (0,60);
  checkipheader.C.in[0] - pim.C.out[0]= (0,60);



  drawelement(checkipheader.A, checkipheader.B, checkipheader.C, pim.A, pim.B, pim.C);


  drawconnect(strip.A,0,0,checkipheader.A);
  drawconnect(strip.B,0,0,checkipheader.B);
  drawconnect(strip.C,0,0,checkipheader.C);

  drawconnect(checkipheader.A,0,0,pim.A);
  drawconnect(checkipheader.B,0,0,pim.B);
  drawconnect(checkipheader.C,0,0,pim.C);




  velementit.classifier(btex \element{~~~~~~~~~~~Classif{}ier(...)~~~~~~~~~~}\lower3.8ex\null etex, 1, 3, agnostic_push);  
  pim.B.out[0] - classifier.in[0] = (0,50);

  velementit.igmp(btex \element{IGMP} etex, 1, 1, push);
  velementit.pimcontrol(btex \element{PIMControl} etex, 0, 1, push);
  velementit.multicasttable(btex \element{MulticastTable} etex, 1, 2, push);
  velementit.pimforwardingtable(btex \element{PIMForwardingTable} etex, 1, 2, push);
  classifier.out[1] - igmp.in[0] = (60,40);
  classifier.s - pimcontrol.n = (160,40);
%  igmp.w - pimcontrol.e = (100,0);
  classifier.out[1] - multicasttable.in[0] = (-100,20);
  velementit.discard(btex \element{Discard} etex, 1, 0, push);
  multicasttable.out[1] - pimforwardingtable.in[0] = (-10,20);
  pimforwardingtable.out[1] - discard.in[0] = (-10,20);
  velementit.lookupiproute(btex \element{~~~~~~~~~~~~~~LookupIPRoute(...)~~~~~~~~~~~~~~} etex, 1, 6, push);
  classifier.out[1] - lookupiproute.in[0] = (0,100);

  drawelement(classifier, igmp, pimcontrol, multicasttable, pimforwardingtable, lookupiproute, discard);

  drawconnect(pimforwardingtable,1,0,discard);

%  drawconnect(pim.A,0,0,classifier);
  drawconnarrow pim.A.out[0]{down} .. tension 2 .. {down}classifier.in[0];
  drawconnect(pim.B,0,0,classifier);

%  drawconnect(pim.C,0,0,classifier);
  drawconnarrow pim.C.out[0]{down} .. tension 2 .. {down}classifier.in[0];

  drawconnect(classifier,1,0,lookupiproute);
  drawconnarrow classifier.out[2]{down} .. tension 2 .. {down}multicasttable.in[0];
  drawconnarrow classifier.out[0]{down} .. tension 2 .. {down}igmp.in[0];
  drawconnect(multicasttable,1,0,pimforwardingtable);
  drawconnarrow multicasttable.out[0]{down} .. tension 2 .. {down}lookupiproute.in[0];
  drawconnarrow igmp.out[0]{down} .. tension 2 .. {down}lookupiproute.in[0];
  drawconnarrow pimcontrol.out[0]{down} .. tension 4 .. {down}lookupiproute.in[0];
  drawconnarrow pimforwardingtable.out[0]{down} .. tension 2 .. {down}lookupiproute.in[0];
  
  velementit.fixpimsrc.A(btex \element{FixPIMSrc(...)} etex, 1, 1, push);
  velementit.fixpimsrc.B(btex \element{FixPIMSrc(...)} etex, 1, 1, push);
  velementit.fixpimsrc.C(btex \element{FixPIMSrc(...)} etex, 1, 1, push);
  velementit.fixpimsrc.D(btex \element{FixPIMSrc(...)} etex, 1, 1, push);
  velementit.fixpimsrc.E(btex \element{FixPIMSrc(...)} etex, 1, 1, push);
  velementit.fixpimsrc.F(btex \element{FixPIMSrc(...)} etex, 1, 1, push);

  velementit.fixipsrc.A(btex \element{FixIPSrc(...)} etex, 1, 1, push);
  velementit.fixipsrc.B(btex \element{FixIPSrc(...)} etex, 1, 1, push);
  velementit.fixipsrc.C(btex \element{FixIPSrc(...)} etex, 1, 1, push);
  velementit.fixipsrc.D(btex \element{FixIPSrc(...)} etex, 1, 1, push);
  velementit.fixipsrc.E(btex \element{FixIPSrc(...)} etex, 1, 1, push);
  velementit.fixipsrc.F(btex \element{FixIPSrc(...)} etex, 1, 1, push);

  velementit.decipttl.A(btex \element{DecIPTTL} etex, 1, 1, push);
  velementit.decipttl.C(btex \element{DecIPTTL} etex, 1, 1, push);
  velementit.decipttl.E(btex \element{DecIPTTL} etex, 1, 1, push);

  lookupiproute.s - decipttl.A.n = (-250,60);
  lookupiproute.s - decipttl.C.n = (-50,60);
  lookupiproute.s - decipttl.E.n = (150,60);

  decipttl.A.s - fixpimsrc.A.n = (0,20);
  lookupiproute.s - fixpimsrc.B.n = (-150,60);
  decipttl.C.s - fixpimsrc.C.n = (0,20);
  lookupiproute.s - fixpimsrc.D.n = (50,60);
  decipttl.E.s - fixpimsrc.E.n = (0,20);
  lookupiproute.s - fixpimsrc.F.n = (250,60);

  fixpimsrc.A.out[0] - fixipsrc.A.in[0] = (0, 20);
  fixpimsrc.B.out[0] - fixipsrc.B.in[0] = (0, 20);
  fixpimsrc.C.out[0] - fixipsrc.C.in[0] = (0, 20);
  fixpimsrc.D.out[0] - fixipsrc.D.in[0] = (0, 20);
  fixpimsrc.E.out[0] - fixipsrc.E.in[0] = (0, 20);
  fixpimsrc.F.out[0] - fixipsrc.F.in[0] = (0, 20);

  drawelement(fixpimsrc.B, fixpimsrc.D, fixpimsrc.F, decipttl.A, decipttl.C, decipttl.E, fixipsrc.A, fixipsrc.B, fixipsrc.C, fixipsrc.D, fixipsrc.E, fixipsrc.F, fixpimsrc.A, fixpimsrc.C, fixpimsrc.E);

  drawconnarrow lookupiproute.out[5]{down} .. tension 4 .. {down}decipttl.A.in[0];
  drawconnarrow lookupiproute.out[4]{down} .. tension 4 .. {down}fixpimsrc.B.in[0];
  drawconnarrow lookupiproute.out[3]{down} .. tension 4 .. {down}decipttl.C.in[0];
  drawconnarrow lookupiproute.out[2]{down} .. tension 4 .. {down}fixpimsrc.D.in[0];
  drawconnarrow lookupiproute.out[1]{down} .. tension 4 .. {down}decipttl.E.in[0];
  drawconnarrow lookupiproute.out[0]{down} .. tension 4 .. {down}fixpimsrc.F.in[0];



  velementit.arpq.A(btex \element{ARPQuerier(...)} etex, 1, 1, push);
  velementit.etherencap.B(btex \element{IPMulticastEtherEncap(...)} etex, 1, 1, push);
  velementit.arpq.C(btex \element{ARPQuerier(...)} etex, 1, 1, push);
  velementit.etherencap.D(btex \element{IPMulticastEtherEncap(...)} etex, 1, 1, push);
  velementit.arpq.E(btex \element{ARPQuerier(...)} etex, 1, 1, push);
  velementit.etherencap.F(btex \element{IPMulticastEtherEncap(...)} etex, 1, 1, push);

%  decipttl.A.n - fixipsrc.A.s = (0,-20);
  etherencap.B.n - fixipsrc.B.s = (0,-20);
%  decipttl.C.n - fixipsrc.C.s = (0,-20);
  etherencap.D.n - fixipsrc.D.s = (0,-20);
%  decipttl.E.n - fixipsrc.E.s = (0,-20);
  etherencap.F.n - fixipsrc.F.s = (0,-20);

  arpq.A.n - fixipsrc.A.s = (0,-20);
  arpq.C.n - fixipsrc.C.s = (0,-20);
  arpq.E.n - fixipsrc.E.s = (0,-20);


  drawelement(arpq.A, etherencap.B, arpq.C, etherencap.D, arpq.E, etherencap.F);


  vqueueit.outq.A(vemptyqueue);
  vqueueit.outq.B(vemptyqueue);
  vqueueit.outq.C(vemptyqueue);

  outq.A.n - arpq.A.s = (-70,-40);
  outq.B.n - arpq.C.s = (-70,-40);
  outq.C.n - arpq.E.s = (-70,-40);

  velementit.out.A(btex \element{ToDevice(eth2)} etex, 1, 0, push);
  velementit.out.B(btex \element{ToDevice(eth1)} etex, 1, 0, push);
  velementit.out.C(btex \element{ToDevice(eth0)} etex, 1, 0, push);

  out.A.n - outq.A.s = (0,-20);
  out.B.n - outq.B.s = (0,-20);
  out.C.n - outq.C.s = (0,-20);

  drawelement(outq.C, outq.B, outq.A, out.C, out.B, out.A);

  drawconnect(fixipsrc.B,0,0,etherencap.B);
  drawconnect(fixipsrc.D,0,0,etherencap.D);
  drawconnect(fixipsrc.F,0,0,etherencap.F);

  drawconnect(fixpimsrc.A,0,0,fixipsrc.A);
  drawconnect(fixpimsrc.B,0,0,fixipsrc.B);
  drawconnect(fixpimsrc.C,0,0,fixipsrc.C);
  drawconnect(fixpimsrc.D,0,0,fixipsrc.D);
  drawconnect(fixpimsrc.E,0,0,fixipsrc.E);
  drawconnect(fixpimsrc.F,0,0,fixipsrc.F);

  drawconnect(fixipsrc.A,0,0,arpq.A);
  drawconnect(fixipsrc.C,0,0,arpq.C);
  drawconnect(fixipsrc.E,0,0,arpq.E);

  drawconnect(decipttl.A,0,0,fixpimsrc.A);
  drawconnect(decipttl.C,0,0,fixpimsrc.C);
  drawconnect(decipttl.E,0,0,fixpimsrc.E);

  drawconnect(arpq.A,0,0,outq.A);
  drawconnect(etherencap.B,0,0,outq.A);
  drawconnect(arpq.C,0,0,outq.B);  
  drawconnect(etherencap.D,0,0,outq.B);  
  drawconnect(arpq.E,0,0,outq.C);
  drawconnect(etherencap.F,0,0,outq.C);

  drawconnect(outq.A,0,0,out.A);
  drawconnect(outq.B,0,0,out.B);  
  drawconnect(outq.C,0,0,out.C);

  % labels
  defaultfont := "Helvetica";
  defaultscale := 1;

  %% classifier A, B, C 
  label.top(btex \portlabel{ARP\\queries} etex scaled 1.2, classifier.A.out[0]+(0,2));
  label.top(btex \portlabel{ARP\\responses} etex scaled 1.2, classifier.A.out[1]+(0,2));  
  label.top(btex \portlabel{IP\\} etex scaled 1.2, classifier.A.out[2]+(0,2));
  label.top(btex \portlabel{non\\IP} etex scaled 1.2, classifier.A.out[3]+(0,2));

  label.top(btex \portlabel{ARP\\queries} etex scaled 1.2, classifier.B.out[0]+(0,2));
  label.top(btex \portlabel{ARP\\responses} etex scaled 1.2, classifier.B.out[1]+(0,2));  
  label.top(btex \portlabel{IP\\} etex scaled 1.2, classifier.B.out[2]+(0,2));
  label.top(btex \portlabel{non\\IP} etex scaled 1.2, classifier.B.out[3]+(0,2));

  label.top(btex \portlabel{non\\IP} etex scaled 1.2, classifier.C.out[0]+(0,2));
  label.top(btex \portlabel{IP\\} etex scaled 1.2, classifier.C.out[1]+(0,2));  
  label.top(btex \portlabel{ARP\\responses} etex scaled 1.2, classifier.C.out[2]+(0,2));
  label.top(btex \portlabel{ARP\\queries} etex scaled 1.2, classifier.C.out[3]+(0,2));

  % 2nd classifier
  label.top(btex \portlabel{IGMP} etex scaled 1.2, classifier.out[0]+(0,2));
  label.top(btex \portlabel{IP} etex scaled 1.2, classifier.out[1]+(0,2));  
  label.top(btex \portlabel{multicast IP} etex scaled 1.2, classifier.out[2]+(0,2));



endfig;

end
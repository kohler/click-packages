require(dhcp)

tun :: KernelTun(1.0.0.1/8);
//tunq :: IPEncap(4, 1.0.0.2, 2.0.0.2)->Queue->tun

tun -> IPPrint(gotIt)
    -> StripIPHeader
    -> Strip(14)
    -> Align(4, 0) 
    -> ip_ch::CheckIPHeader(CHECKSUM true)
    -> CheckUDPHeader
    -> CheckDHCPMsg(request)
    -> Print(Discarding)
    -> Discard;


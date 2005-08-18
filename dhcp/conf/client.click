require(dhcp)

client::DHCPClient(52:54:00:E5:33:17);
//udp_encap::UDPIPEncap( 192.168.10.10 , 68, 255.255.255.255, 67 );
udp_encap::UDPIPEncap( 0.0.0.0 , 68, 255.255.255.255, 67 );

eth_encap::EtherEncap( 0x0800, 52:54:00:E5:33:17 , ff:ff:ff:ff:ff:ff);

from_dev :: FromDevice(eth0)
	->Strip(14)
	->Align(4, 0) 
	->ip_check::CheckIPHeader(CHECKSUM true, DETAILS true)
	->ipclass :: IPClassifier(icmp, udp, tcp, -)

ipclass[0]->Print(<icmp>)->Discard;
ipclass[2]->Print(<tcp>)->Discard;
ipclass[3]->Print(<???>)->Discard;

ipclass[1]
	->udp_check::CheckUDPHeader(DETAILS true)
	->CheckDHCPMsg(reply)
       	->[0]client;

ip_check[1]->Print("Bad IP")->Discard;
//udp_check[1]->Print("Bad UDP")->Discard;

// client[0] broadcast
// client[1] unicast

client[0] -> Print(<dhcpMsg>)
          -> udp_encap
	  -> eth_encap
	  -> q :: Queue(1000)
	  -> to_dev :: ToDevice(eth0)

queue::DHCPOfferMsgQueue(client.client_ip_read) -> [1]client; //pull 

client[1] -> udp_encap1::UDPIPEncap( 0.0.0.0 , 68, 192.168.10.9, 67 )
	  -> DHCPUnicastEncap(client.client_ip_read, client.server_ip_read)
	  -> eth_encap
	  -> q ; 

client[2] -> queue;
client[3] -> Discard;


//DriverManager(
//	wait_time 1s,
//	write client.client_write 192.168.0.2 192.168.0.1 1110180078 1170180090,
//	wait_time 2s,
	//save  client.lease_read client.lease,
//	wait_time 20s,
//	write client.release_write blah,
//	loop);
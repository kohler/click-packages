require(dhcp);

//test :: SamplePackageElement;

FromDevice(eth0)->class::Classifier( 12/0806 20/0001,
			  	 12/0806 20/0002,
			           12/0800,
	        		   -);

class[0]->Print(<ARP_REQ>)->Discard;
class[1]->Print(<ARP_REP>)->Discard;
class[2]->Print(<IP>)
	->Strip(14)
	->Align(4, 0) 
	->ip_check::CheckIPHeader(CHECKSUM true, DETAILS true)->Discard;


class[3]->Print(<??????>)->Discard;


//QuitWatcher(test);

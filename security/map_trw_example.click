
// Classifies into IP, ARP, and other
only_ip0 :: Classifier(12/0800, 12/0806, -);
only_ip1 :: Classifier(12/0800, 12/0806, -);


toEth0 :: Queue;
toEth1 :: Queue;

trw :: MapTRW(10.10.1.254, CA:FE:BA:BE:00:01, 255.255.255.0, IP_TABLE_MIN_COUNT -15, IP_TABLE_MAX_COUNT 20,
        IP_TABLE_BLOCK_COUNT 5);


FromDevice(eth2, PROMISC true) -> only_ip0[0] -> MarkIPHeader(14) -> 
	[0]trw[0] -> toEth1 -> ToDevice(eth1);

only_ip0[1] -> [0]trw;
only_ip0[2] -> toEth1;

FromDevice(eth1, PROMISC true) -> only_ip1[0] -> MarkIPHeader(14) -> 
	[1]trw[1]-> toEth0 ->
	ToDevice(eth2);

only_ip1[1] -> [1]trw;
only_ip1[2] -> toEth0;
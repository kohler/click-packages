require(aggregates);

FromDump("-",STOP true,FORCE_IP true)
    -> allpktcount::Counter()
    -> classifier::IPClassifier(tcp,-);

classifier[0]
    -> tcppktcount::Counter()
    -> tcpc::TCPCounter()
    -> Discard;

classifier[1]
    -> Discard;

DriverManager(wait_pause,
	        print allpktcount.count,
		print tcppktcount.count);
	

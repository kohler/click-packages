require(aggregates);

FromDump("-",STOP true,FORCE_IP true)
    -> allpktcount::Counter()
    -> classifier::IPClassifier(tcp port 80,-);

classifier[0]
    -> webpktcount::Counter()
    -> onoff::OnOffModel(5,3600) 
    -> Discard;

classifier[1]
    -> Discard;

DriverManager(wait_pause,
	        print allpktcount.count,
		print webpktcount.count,
		write onoff.write_ascii_file master-onoff-att01,
		stop);
	

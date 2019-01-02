build:
	g++ -gdwarf-2 -o inhttp inhttp.cpp /usr/local/lib/libnet.a /usr/local/lib/libpcap.a -lpthread
clean:
	rm -rf inhttp

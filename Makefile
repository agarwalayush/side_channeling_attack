all: attack encrypt
clean:
	rm -f *.o spy attack encrypt
spy: spy.cpp ../../cacheutils.h
	g++ -std=gnu++11 -O2 -o $@ $< -Iopenssl -L./ -lcrypto

attack: 2_spy.cpp ../../cacheutils.h
	g++ -std=gnu++11 -O2 -o $@ $< -Iopenssl -L./ -lcrypto -pthread

encrypt: encrypt.cpp ../../cacheutils.h
	g++ -std=gnu++11 -O2 -o $@ $< -Iopenssl -L./ -lcrypto

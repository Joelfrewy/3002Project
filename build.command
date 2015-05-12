gcc director.c -o director
gcc -Wall -o analyst analyst.c -L/usr/lib -lssl -lcrypto
gcc -Wall -o collector collector.c -L/usr/lib -lssl -lcrypto
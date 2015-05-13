gcc -Wno-deprecated-declarations director.c -o director
gcc -Wno-deprecated-declarations -o bank bank.c -L/usr/lib -lssl -lcrypto
gcc -Wno-deprecated-declarations -o analyst analyst.c -L/usr/lib -lssl -lcrypto
gcc -Wno-deprecated-declarations -o collector collector.c -L/usr/lib -lssl -lcrypto
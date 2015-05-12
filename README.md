# 3002Project

this is the template for the CITS3002 2015 semester 1 project
it was set up in eclipse with the c/c++ plugin

it contains 4 C project folders containing each of the source code files (collector, analyst, bank, director)

Instructions:

***** PART 1 - Building the Executables *****

1. open the terminal
2. navigate to folder with source codes

        "cd Documents/CITS3002/Project"

3.      
            compile the three source files into executables:
            director: 
                "gcc director.c -o director"
            analyst: 
                "gcc -Wall -o analyst analyst.c -L/usr/lib -lssl -lcrypto"
            collector: 
                "gcc -Wall -o collector collector.c -L/usr/lib -lssl -lcrypto"
        
                            ***** or *****

            type this:
                "./build.command"


***** PART 2 - Launching the Project *****

1. open three terminals, navigate to file locations

2. launch director in terminal 1
        "./director 32001"

3. launch analyst as root in terminal 2
        "sudo ./analyst 5000 127.0.0.1 32001"

4. launch collector in terminal 3
        "./collector 5001 127.0.0.1 32001"


***** PART 3 - Using the Project *****

1. enter a message into the collector terminal (3)
        "hello"

2. there should be a recieved message in analyst terminal (2). enter a message into the analyst terminal (2)
        "goodbye"

3. there should be a recieved message in collector terminal (3)
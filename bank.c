/* 
 *  A simple TCP proxy
 *  by Martin Broadhurst (www.martinbroadhurst.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>



int main(int argc, char **argv)
{
    printf("                                                                                  --                \n");
    printf("                                              `oosssssso+/-`                    `hosy`              \n");
    printf("                                              /d-....-:::/+sysso+ssssssssssso:.`h/:-od`             \n");
    printf("                                              oy..---:://+oooyyo/-........`.-/shy/o::sh             \n");
    printf("                                    `:/osyhyyymy.-------:shs/---........````````./yy/:ds            \n");
    printf("                               `:ohdhs+:-.....sy.---::/hh+----...........`````````.-oyoM`           \n");
    printf("                            .odds+-.........--oh--:::yd/:----.................`````...sN+           \n");
    printf("                         `+ddo:--...........--+m--:/mo:::---.......:o/...............ss/d.          \n");
    printf("                       .sNy:---...```````....-:N:-om/:::---........NMMo.............:MMy-d:         \n");
    printf("                     `yms:----.````````````..--m/+m::::----.......-MMMd.............-NMy.:N.        \n");
    printf("          -yhyyy/   +Ny:----.```````````````.--syN/:::----........-NMMy.........-::-.:o-..oy        \n");
    printf("       -oyMd/  `/h+yN/---...````````````````---:Ns::::-::-.........-++.....-oyyysooossss+-.m        \n");
    printf("      sh-oM-mo   `mm:---...````````````````.---/N::::::::-...............+hy+:-....````.:osm-       \n");
    printf("     `h  -mhm-   +N/---...`````````````````.---sd::::::::............../ds::+:.....```````.+m.      \n");
    printf("      +          Ns:---..``````````````````----yh:::::::-...........--sm/-++................oy      \n");
    printf("                -N::---..````````````````..--::sd:::::::-..........--+N:-:o....:dNNy....-hmh-N      \n");
    printf("                +d-----.```````````````....::::+N:::::::-..........--hy--+/....dNNNN/...yNNN-N      \n");
    printf("                +h:----.````````````.......-::::ms::::::--.........--dy--+:....oNNNN-...oNNyys      \n");
    printf("                +d:---......`...............::::+N/:::::--.........--+N:-:o......:/-......-yh`      \n");
    printf("                +N:---......................-::::om/::::---..........-omo-/+............-sm+        \n");
    printf("                :M/:--.......................-::::+mo:::----...........:shhss/-...-:/+yhy/`         \n");
    printf("                `M+:--.........................-::::yd+::----.............-/ossssssyNN+             \n");
    printf("                 ds:--...........................-:::/ydy/----..................:odh/               \n");
    printf("                 sd:--........................--...-----sydhs+/-...........-/ohds/`                 \n");
    printf("                 /N:--.........:--...........+--......../mNy+osyhhhhhhhhhhys+:`                     \n");
    printf("                 `No--.........y::::---.....-h--........oymo:::::::--+y                             \n");
    printf("                  om:-........sddmhyso++////od--........somo:::-.....ss       GIVE ME MONEY !!!!    \n");
    printf("                  `md/-......:N.  so+osyyyhmsN:-........d/hs:::......N-                             \n");
    printf("                   :MNmyo+/:/m+   :mso/:::d:`M/-.......-N`od:::.....sy                              \n");
    printf("                    +MNNNNNNMs     yNNNNNMo  ds:.......ys -Mmhysosydm`                              \n");
    printf("                     /NNNNNMs       dNdMNo   +m/-...-:+m`  hMNNMNNNd.                               \n");
    printf("                      .:`yN+        ./ :.     mMNNNNNNM:   -MNN/MNs                                 \n");
    printf("                                              -NNNNNNN+     ./` ..                                  \n");
    printf("                                               .yNmo:-                                              \n");
}


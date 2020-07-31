#include <pcap.h>
#include <stdio.h>
#include "capture.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    packet_capture(argv[1]);
}

#!/usr/bin/env bash
set -e
g++ -std=c++17 -O2 -I include -o dpi_engine \
    src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
echo "Built ./dpi_engine"

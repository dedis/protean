#!/usr/bin/env bash

python3.11 process_data.py ../microbenchmarks/verify/test_data/save/verify_kv.csv v_kv > data/v_kv.csv
python3.11 process_data.py ../microbenchmarks/verify/test_data/save/verify_opc.csv v_opc > data/v_opc.csv

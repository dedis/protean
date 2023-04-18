#!/usr/bin/env bash

#python3.11 process_data.py ../microbenchmarks/verify/test_data/vm_local/local_kv.csv -l kv > data/kv_local.csv
#python3.11 process_data.py ../microbenchmarks/verify/test_data/vm_local/local_opc.csv -l opc > data/opc_local.csv

#python3.11 process_data.py ../microbenchmarks/verify/test_data/verify_kv.csv kv > data/kv.csv
python3.11 process_data.py ../microbenchmarks/verify/test_data/vopc_v1.csv opc > data/opc.csv
python3.11 process_data.py ../microbenchmarks/sign/test_data/sign_v1.csv sign > data/sign.csv

#python3.11 process_data.py ../microbenchmarks/shuffle/test_data/shuffle_regular.csv shuf > data/shuf_reg.csv
#python3.11 process_data.py ../microbenchmarks/shuffle/test_data/shuffle_dfu.csv shuf > data/shuf_dfu.csv

#python3.11 process_data.py ../microbenchmarks/threshold/test_data/threshold_regular.csv dec > data/dec_reg.csv
#python3.11 process_data.py ../microbenchmarks/threshold/test_data/threshold_dfu.csv dec > data/dec_dfu.csv

python3.11 process_data.py ../randlottery/test_data/randlottery_v1.csv rlot
python3.11 process_data.py ../dkglottery/test_data/dkglottery_v0.csv dlot
python3.11 process_data.py ../evoting/test_data/evoting_v0.csv evote

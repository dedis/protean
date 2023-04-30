#!/usr/bin/env bash

#python3.11 process_data.py ../microbenchmarks/verify/test_data/save/vkv_v1.csv kv > data/kv.csv
#python3.11 process_data.py ../microbenchmarks/verify/test_data/save/vopc_v1.csv opc > data/opc.csv
#python3.11 process_data.py ../microbenchmarks/sign/test_data/save/sign_v1.csv sign > data/sign.csv

#python3.11 process_data.py ../microbenchmarks/shuffle/test_data/shuffle_regular.csv shuf > data/shuf_reg.csv
#python3.11 process_data.py ../microbenchmarks/shuffle/test_data/shuffle_dfu.csv shuf > data/shuf_dfu.csv

#python3.11 process_data.py ../microbenchmarks/threshold/test_data/threshold_regular.csv dec > data/dec_reg.csv
#python3.11 process_data.py ../microbenchmarks/threshold/test_data/threshold_dfu.csv dec > data/dec_dfu.csv

python3.11 process_data.py ../randlottery/test_data/randlottery_v2.csv rlot
python3.11 process_data.py ../dkglottery/test_data/dkglottery_v3.csv dlot
python3.11 process_data.py ../evoting/test_data/evoting_v2.csv evote

python3.11 process_data.py ../randlottery/test_data/rl_batch.csv rlot -b -o batch
python3.11 process_data.py ../dkglottery/test_data/dkg_batch.csv dlot -b -o batch
python3.11 process_data.py ../evoting/test_data/ev_batch.csv evote -b -o batch

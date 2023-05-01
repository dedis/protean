#!/usr/bin/env bash

python3.11 process_data.py ../microbenchmarks/verify/test_data/save/vkv_v2.csv kv > data/kv.csv
python3.11 process_data.py ../microbenchmarks/verify/test_data/save/vopc_v1.csv opc > data/opc.csv
python3.11 process_data.py ../microbenchmarks/sign/test_data/save/sign.csv sign > data/sign.csv

python3.11 process_data.py ../microbenchmarks/shuffle/test_data/save/shuffle_regular.csv shuf > data/shuf_reg.csv
python3.11 process_data.py ../microbenchmarks/shuffle/test_data/save/shuffle_dfu.csv shuf > data/shuf_dfu.csv

python3.11 process_data.py ../microbenchmarks/threshold/test_data/save/threshold_regular.csv dec > data/dec_reg.csv
python3.11 process_data.py ../microbenchmarks/threshold/test_data/save/threshold_dfu.csv dec > data/dec_dfu.csv

python3.11 process_data.py ../randlottery/test_data/save/randlottery.csv rlot
python3.11 process_data.py ../dkglottery/test_data/save/dkglottery.csv dlot
python3.11 process_data.py ../evoting/test_data/save/evoting.csv evote

python3.11 process_data.py ../randlottery/test_data/save/rl_batch.csv rlot -b
python3.11 process_data.py ../dkglottery/test_data/save/dkg_batch.csv dlot -b
python3.11 process_data.py ../evoting/test_data/save/ev_batch.csv evote -b

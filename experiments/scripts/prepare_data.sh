#!/usr/bin/env bash

#python3.11 process_data.py ../microbenchmarks/verify/test_data/save/old-bls/vkv_v3.csv kv > data/kv.csv
#python3.11 process_data.py ../microbenchmarks/verify/test_data/save/old-bls/vopc_v1.csv opc > data/opc.csv
#python3.11 process_data.py ../microbenchmarks/sign/test_data/save/old-bls/sign.csv sign > data/sign.csv

#python3.11 process_data.py ../microbenchmarks/shuffle/test_data/save/old-bls/shuffle_regular.csv shuf > data/shuf_reg.csv
#python3.11 process_data.py ../microbenchmarks/shuffle/test_data/save/old-bls/shuffle_dfu.csv shuf > data/shuf_dfu.csv

#python3.11 process_data.py ../microbenchmarks/threshold/test_data/save/old-bls/threshold_regular.csv dec > data/dec_reg.csv
#python3.11 process_data.py ../microbenchmarks/threshold/test_data/save/old-bls/threshold_dfu.csv dec > data/dec_dfu.csv

#python3.11 process_data.py ../randlottery/test_data/save/randlottery.csv rlot
#python3.11 process_data.py ../dkglottery/test_data/save/dkglottery.csv dlot
#python3.11 process_data.py ../evoting/test_data/save/evoting.csv evote

#python3.11 process_data.py ../randlottery/test_data/save/randlottery.csv rlot
#python3.11 process_data.py ../dkglottery/test_data/save/dkglottery_v2.csv dlot
#python3.11 process_data.py ../evoting/test_data/save/evoting_v2.csv evote

python3.11 process_data.py ../randlottery/test_data/randlottery_batch.csv rlot -b
python3.11 process_data.py ../dkglottery/test_data/dkglottery_batch.csv dlot -b
python3.11 process_data.py ../evoting/test_data/evoting_batch.csv evote -b

python3.11 process_data.py ../microbenchmarks/verify/test_data/verify_kv.csv kv > data/kv.csv
python3.11 process_data.py ../microbenchmarks/verify/test_data/save/verify_opc.csv opc > data/opc.csv
python3.11 process_data.py ../microbenchmarks/sign/test_data/bdn.csv sign > data/sign.csv

python3.11 process_data.py ../microbenchmarks/shuffle/test_data/shuffle_reg.csv shuf > data/shuf_reg.csv
python3.11 process_data.py ../microbenchmarks/shuffle/test_data/shuffle_dfu.csv shuf > data/shuf_dfu.csv

python3.11 process_data.py ../microbenchmarks/threshold/test_data/threshold_reg.csv dec > data/dec_reg.csv
python3.11 process_data.py ../microbenchmarks/threshold/test_data/threshold_dfu.csv dec > data/dec_dfu.csv

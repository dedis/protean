#!/usr/bin/env bash

### Microbenchmarks

python3.11 process_data.py ../randlottery/test_data/save/randlottery_batch.csv rlot -b
python3.11 process_data.py ../dkglottery/test_data/save/dkglottery_batch.csv dlot -b
python3.11 process_data.py ../evoting/test_data/save/evoting_batch.csv evote -b

python3.11 process_data.py ../microbenchmarks/verify/test_data/verify_kv.csv kv > data/kv.csv
python3.11 process_data.py ../microbenchmarks/verify/test_data/save/verify_opc.csv opc > data/opc.csv
python3.11 process_data.py ../microbenchmarks/sign/test_data/save/bdn.csv sign > data/sign.csv

python3.11 process_data.py ../microbenchmarks/shuffle/test_data/save/shuffle_reg.csv shuf > data/shuf_reg.csv
python3.11 process_data.py ../microbenchmarks/shuffle/test_data/save/shuffle_dfu.csv shuf > data/shuf_dfu.csv

python3.11 process_data.py ../microbenchmarks/threshold/test_data/save/threshold_reg.csv dec > data/dec_reg.csv
python3.11 process_data.py ../microbenchmarks/threshold/test_data/save/threshold_dfu.csv dec > data/dec_dfu.csv

### Applications

python3.11 process_data.py ../randlottery/test_data/save/randlot_1.csv rlot
python3.11 process_data.py ../dkglottery/test_data/save/dkglot_1.csv dlot
python3.11 process_data.py ../evoting/test_data/save/ev_1.csv evote

#python3.11 process_data.py ../randlottery/test_data/save/randlottery.csv rlot
#python3.11 process_data.py ../dkglottery/test_data/save/dkglottery_v2.csv dlot
#python3.11 process_data.py ../evoting/test_data/save/evoting_v2.csv evote

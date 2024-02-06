#!/usr/bin/env bash

DKGLOT_DIR="./dkglottery/test_data/save/"
RANDLOT_DIR="./randlottery/test_data/save/"
EV_DIR="./evoting/test_data/save/"

touch $DKGLOT_DIR/dkglot_multi.csv
touch $RANDLOT_DIR/randlot_multi.csv
touch $EV_DIR/ev_multi.csv

head -n1 $DKGLOT_DIR/dkglot_1.csv >> $DKGLOT_DIR/dkglot_multi.csv
head -n1 $RANDLOT_DIR/randlot_1.csv >> $RANDLOT_DIR/randlot_multi.csv
head -n1 $EV_DIR/ev_1.csv >> $EV_DIR/ev_multi.csv

for i in {1..10}
do
        tail -n7 $DKGLOT_DIR/dkglot_$i.csv >> $DKGLOT_DIR/dkglot_multi.csv
        tail -n7 $RANDLOT_DIR/randlot_$i.csv >> $RANDLOT_DIR/randlot_multi.csv
        tail -n7 $EV_DIR/ev_$i.csv >> $EV_DIR/ev_multi.csv
done

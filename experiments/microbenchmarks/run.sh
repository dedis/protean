#!/usr/bin/env bash

cd threshold; go clean; go build;
#./threshold -platform mininet threshold_dfu.toml
#pkill -9 -f "ExitOnForward"
#ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
sleep 360
./threshold -platform mininet threshold_reg.toml
pkill -9 -f "ExitOnForward"
ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
sleep 300

cd ../shuffle; go clean; go build;
./shuffle -platform mininet shuffle_dfu.toml
pkill -9 -f "ExitOnForward"
ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
sleep 300
./shuffle -platform mininet shuffle_reg.toml
pkill -9 -f "ExitOnForward"
ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
sleep 300

cd ../sign; go clean; go build;
./sign -platform mininet bdn.toml
pkill -9 -f "ExitOnForward"
ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
sleep 300

cd ../verify; go clean; go build;
./verify -platform mininet verify_opc.toml
pkill -9 -f "ExitOnForward"
ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
sleep 300

rm -r build/ deploy; go clean; go build;
./verify -platform mininet verify_kv.toml

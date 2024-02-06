#!/usr/bin/env bash

cd evoting; go clean; go build;
./evoting -platform mininet evoting.toml
pkill -9 -f "ExitOnForward"
#ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
sleep 300

#cd ../dkglottery; go clean; go build;
#./dkglottery -platform mininet dkglottery.toml
#pkill -9 -f "ExitOnForward"
##ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
#sleep 300

cd ../randlottery; go clean; go build;
./randlottery -platform mininet randlottery.toml
pkill -9 -f "ExitOnForward"
##ssh cey@localhost 'sudo /etc/init.d/openvswitch-switch restart'
#sleep 300

import csv
import sys
import re
import argparse
import os
import numpy as np

jv_header = ['num_participants', 'avg', 'min', 'max']
txn_header = ['num_participants', 'total']

BASE_DIR = "data"

DKGLOTTERY = "dkglottery"
RANDLOTTERY = "randlottery"
EVOTING = "evoting"
SETUP = "setup"
JOIN = "join"
VOTE = "vote"
CLOSE = "close"
LOCK = "lock"
SHUFFLE = "shuffle"
TALLY = "tally"
FINALIZE = "finalize"

vpattern = 'verify_(\d+)_(\d+)_wall_avg'
vpattern_min = 'verify_(\d+)_(\d+)_wall_min'
vpattern_max = 'verify_(\d+)_(\d+)_wall_max'

vpattern_local = 'verify_local_(\d+)_(\d+)_wall_avg'

spattern = 'sign_(\d+)_(\d+)_wall_avg'

setup_pattern = "setup_(\w+)_wall_avg"
lpattern = "lock_(\w+)_wall_avg"
shuf_pattern = "shuffle_(\w+)_wall_avg"
tpattern = "tally_(\w+)_wall_avg"
cpattern = "close_(\w+)_wall_avg"
fpattern = "finalize_(\w+)_wall_avg"

cwd = os.getcwd()

def read_data(fname):
    with open(fname, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        labels = next(reader)
        data_read = []
        for row in reader:
            data_read.append(dict(zip(labels, row)))
    return data_read

def process_kv(data_read, local):
    data = dict()
    for label, value in data_read[0].items():
        if local:
            match = re.search(vpattern_local, label)
        else:
            match = re.search(vpattern, label)
        if match is not None:
            input_num = int(match.group(1))
            blk_num = int(match.group(2))
            if blk_num > 5:
                if input_num not in data:
                    data[input_num] = {blk_num: value}
                else:
                    d = data[input_num]
                    d[blk_num] = value

    print("input_num,block_num,total")
    for input_num, val_dict in sorted(data.items()):
        for blk_num, val in sorted(val_dict.items()):
            print("%d,%d,%.6f" % (input_num, blk_num, float(val)))

def process_opc(data_read, local):
    data = dict()
    for label, value in data_read[0].items():
        if local:
            match = re.search(vpattern_local, label)
        else:
            match = re.search(vpattern, label)
        if match is not None:
            input_num = int(match.group(1))
            data_size = int(match.group(2))
            if data_size > 4096:
                if input_num not in data:
                    data[input_num] = {data_size: value}
                else:
                    d = data[input_num]
                    d[data_size] = value

    print("input_num,data_size,total")
    for input_num, val_dict in sorted(data.items()):
        for data_size, val in sorted(val_dict.items()):
            print("%d,%d,%.6f" % (input_num, data_size, float(val)))

def process_sign(data_read, local):
    data = dict()
    for label, value in data_read[0].items():
        if local:
            match = re.search(spattern_local, label)
        else:
            match = re.search(spattern, label)
        if match is not None:
            output_num = int(match.group(1))
            data_size = int(match.group(2))
            if data_size > 4096:
                if output_num not in data:
                    data[output_num] = {data_size: value}
                else:
                    d = data[output_num]
                    d[data_size] = value

    print("output_num,data_size,total")
    for output_num, val_dict in sorted(data.items()):
        for data_size, val in sorted(val_dict.items()):
            print("%d,%d,%.6f" % (output_num, data_size, float(val)))

def process_dfu_mb(data_read, prefix):
    data = dict()
    label = prefix + "_wall_avg"
    for dr in data_read:
        num_ctexts = int(dr['numciphertexts'])
        if num_ctexts > 5:
            data[num_ctexts] = float(dr[label])

    print("num_ctexts,total")
    for k in data:
        print("%d,%6f" % (k,data[k]))

def process_jv(data_read, app_type, txn_type):
    latency_vals = dict()
    for dr in data_read:
        num_participants = int(dr['numparticipants'])
        if num_participants > 5:
            vals = list()
            for i in range(num_participants):
                val = float(dr[f'p{i}_{txn_type}_wall_avg'])
                vals.append(val)
                # print(i, val)
            latency_vals[num_participants] = vals

    fpath = os.path.join(cwd, BASE_DIR, app_type, f'{txn_type}.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(jv_header)
        for k in latency_vals:
            vals = np.array(latency_vals[k])
            min_val = vals.min()
            max_val = vals.max()
            mean_val = vals.mean()
            data = [k, mean_val, min_val, max_val]
            writer.writerow(data)
            # print("%d,%.6f,%.6f,%.6f" % (k, mean_val, min_val, max_val))

def process_txn(data_read, app_type, txn_type, pattern):
    print(">>>", txn_type)
    fpath = os.path.join(cwd, BASE_DIR, app_type, f'{txn_type}.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(txn_header)
        data = dict()
        for dr in data_read:
            num_participants = int(dr['numparticipants'])
            if num_participants > 5:
                total = 0.0
                for label, value in dr.items():
                    match = re.search(pattern, label)
                    if match is not None and match.group(1) != "getstate":
                        total += float(value)
                data = [num_participants, total]
                writer.writerow(data)
                print("%d,%.6f" % (num_participants, total))

def process_randlot(data_read):
    process_jv(data_read, RANDLOTTERY, JOIN)
    process_txn(data_read, RANDLOTTERY, CLOSE, cpattern)
    process_txn(data_read, RANDLOTTERY, FINALIZE, fpattern)

def process_dkglot(data_read):
    process_jv(data_read, DKGLOTTERY, JOIN)
    process_txn(data_read, DKGLOTTERY, SETUP, setup_pattern)
    process_txn(data_read, DKGLOTTERY, CLOSE, cpattern)
    process_txn(data_read, DKGLOTTERY, FINALIZE, fpattern)

def process_evote(data_read):
    process_jv(data_read, EVOTING, VOTE)
    process_txn(data_read, EVOTING, SETUP, setup_pattern)
    process_txn(data_read, EVOTING, LOCK, lpattern)
    process_txn(data_read, EVOTING, SHUFFLE, shuf_pattern)
    process_txn(data_read, EVOTING, TALLY, tpattern)

def dump_kv(data_read):
    data = dict()
    for label, value in data_read[0].items():
        avg_match = re.search(vpattern, label)
        # max_match = re.search(vpattern_max, label)
        # if avg_match is not None and min_match is not None and max_match is not None:
        if avg_match is not None:
            input_num = int(avg_match.group(1))
            blk_num = int(avg_match.group(2))
            if blk_num > 5:
                if input_num not in data:
                    data[input_num] = {blk_num: [value]}
                else:
                    d = data[input_num]
                    d[blk_num] = [value]

    for label, value in data_read[0].items():
        min_match = re.search(vpattern_min, label)
        if min_match is not None:
            input_num = int(min_match.group(1))
            blk_num = int(min_match.group(2))
            if blk_num > 5:
                d = data[input_num]
                d[blk_num].append(value)

    for label, value in data_read[0].items():
        max_match = re.search(vpattern_max, label)
        if max_match is not None:
            input_num = int(max_match.group(1))
            blk_num = int(max_match.group(2))
            if blk_num > 5:
                d = data[input_num]
                d[blk_num].append(value)


    print("input_num,block_num,avg,min,max")
    for input_num, val_dict in sorted(data.items()):
        for blk_num, val in sorted(val_dict.items()):
            print("%d,\t%d,\t%.6f,\t%.6f,\t%.6f" % (input_num, blk_num,
                                            float(val[0]), float(val[1]),
                                            float(val[2])))

def main():
    parser = argparse.ArgumentParser(description='Parsing csv files')
    parser.add_argument('fname', type=str)
    parser.add_argument('exp_type', choices=['kv', 'opc', 'sign', 'shuf',
                                             'dec', 'rlot', 'dlot', 'evote'], type=str)
    parser.add_argument('-l', dest='local', action='store_true')
    parser.add_argument('-d', dest='dump', action='store_true')
    args = parser.parse_args()
    data_read = read_data(args.fname)
    if "kv" in args.exp_type:
        if args.dump:
            dump_kv(data_read)
        else:
            process_kv(data_read, args.local)
    elif "opc" in args.exp_type:
        if args.dump:
            dump_opc(data_read)
        else:
            process_opc(data_read, args.local)
    elif "sign" in args.exp_type:
        process_sign(data_read, args.local)
    elif "shuf" in args.exp_type:
        process_dfu_mb(data_read, "shuffle")
    elif "dec" in args.exp_type:
        process_dfu_mb(data_read, "decrypt")
    elif "rlot" in args.exp_type:
    		process_randlot(data_read)
    elif "dlot" in args.exp_type:
    		process_dkglot(data_read)
    elif "evote" in args.exp_type:
        process_evote(data_read)

if __name__ == '__main__':
    main()

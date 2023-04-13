import csv
import sys
import re
import argparse

vpattern = 'verify_(\d+)_(\d+)_wall_avg'
vpattern_local = 'verify_local_(\d+)_(\d+)_wall_avg'
spattern = 'sign_(\d+)_(\d+)_wall_avg'

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

def process_evote(data_read, local):
    data = dict()
    for dr in data_read:
        num_participants = int(dr['numparticipants'])
        vals = list()
        for i in range(num_participants):
            vals.append(float(dr[f'p{i}_vote_wall_avg']))
        data[num_participants] = vals

    for k in data:
        data[k].sort()
        print("%d" % (k), end='')
        for v in data[k]:
            print(",%6f" % (v), end='')
        print()



def main():
    parser = argparse.ArgumentParser(description='Parsing csv files')
    parser.add_argument('fname', type=str)
    parser.add_argument('exp_type', choices=['v_kv', 'v_opc', 'sign', 'evote'], type=str)
    parser.add_argument('-l', dest='local', action='store_true')
    args = parser.parse_args()
    data_read = read_data(args.fname)
    if "kv" in args.exp_type:
        process_kv(data_read, args.local)
    elif "opc" in args.exp_type:
        process_opc(data_read, args.local)
    elif "sign" in args.exp_type:
        process_sign(data_read, args.local)
    elif "evote" in args.exp_type:
        process_evote(data_read, args.local)

if __name__ == '__main__':
    main()

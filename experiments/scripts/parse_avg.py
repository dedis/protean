import sys
import csv
import re
import pandas as pd

def parse_file(fpath, txn_type, stat_type):
    rows = list()
    idx_dict = dict()
    with open(fpath, 'r') as file:
        for line in file:
            rows.append(line.rstrip())

    label_regex = re.compile('p.*_'+txn_type+'_wall_'+stat_type)
    labels = rows[0].split(',')
    for i in range(len(labels)):
        if label_regex.match(labels[i]) is not None:
            idx_dict[labels[i]] = i

    value_dict = dict()
    for i in range(1,len(rows)):
        row = rows[i].split(',')
        for label in idx_dict:
            idx = idx_dict[label]
            if label in value_dict:
                value_dict[label].append(row[idx])
            else:
                value_dict[label] = [row[idx]]
    print(value_dict)

def parse_pandas(fpath, txn_type, stat_type):
    df = pd.read_csv(fpath, header=0)
    print(df)

def main():
    if len(sys.argv) < 4:
        sys.exit("missing args: input_file txn_type stat_type")
    # parse_file(sys.argv[1], sys.argv[2], sys.argv[3])
    parse_pandas(sys.argv[1], sys.argv[2], sys.argv[3])

if __name__ == "__main__":
    main()


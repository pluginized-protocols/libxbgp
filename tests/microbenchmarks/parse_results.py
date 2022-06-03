import csv
import statistics
import sys

import matplotlib.pyplot as plt


def read_csv(str_file: str):
    parsed_csv = {}
    with open(str_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            fn_name = row['fn_name']
            if fn_name not in parsed_csv:
                parsed_csv[fn_name] = {
                    'sample': []
                }

            sec = int(row['secs'])
            nanosecs = int(row['nanosecs'])

            tot_time = (sec * (10 ** 9)) + nanosecs
            parsed_csv[fn_name]['sample'].append(tot_time)
    return parsed_csv


def main(str_file: str):
    exps = read_csv(str_file)

    data = []
    x_label = []

    i = 0
    tup = [-1, -1]

    for exp_name, x in exps.items():
        tup[i] = statistics.median_low(x['sample'])
        print(f"{exp_name},{tup[i]}")
        i += 1
        if i == 2:
            i = 0
            print(100*((tup[1]/tup[0])-1))

        data.append(x['sample'])
        x_label.append(exp_name)

    plt.boxplot(data, labels=x_label)
    plt.show()


if __name__ == '__main__':
    main(sys.argv[1])

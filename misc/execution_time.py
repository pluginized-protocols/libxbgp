#! /usr/bin/env python3

import matplotlib.pyplot as plt
import json
from sys import argv


def get_execution_time(file):
    init_time = -1

    relevant_info = []

    def d_time(curr):
        return curr - init_time

    with open(file, 'r') as f:
        for line in f:
            data = json.loads(line)

            if init_time < 0:
                init_time = data['time']

            if d_time(data['time']) / (10 ** 9) > 575:

                if (data['info']['cpu_percent']) > 20:
                    relevant_info.append({
                        'time': d_time(data['time']),
                        'cpu': data['info']['cpu_percent']
                    })

    return relevant_info


def main2():
    a = get_execution_time("/home/thomas/Documents/BGP_perf/1decplug/out.res.perf04")

    time = [i['time'] / (10 ** 9) for i in a]
    cpu = [i['cpu'] for i in a]

    plt.plot(time, cpu, label="Recvd and processed prefixes (ubpf disabled)")
    plt.grid()
    plt.show()


def main():
    exec_time = []

    for i in range(1, len(argv)):
        a = get_execution_time(argv[i])
        file = argv[i].split('/')

        time = [i['time'] / (10 ** 9) for i in a]
        cpu = [i['cpu'] for i in a]

        exec_time.append({
            'file': file[len(file) - 1],
            'time': a[len(a) - 1]['time'] - a[0]['time'],
        })

        # plt.plot(time, cpu, label="Recvd and processed prefixes (ubpf disabled)")
        # plt.grid()
        # plt.show()

    for a in exec_time:
        print(a)


if __name__ == '__main__':
    # main2()
    main()

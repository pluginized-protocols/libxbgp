import json

import matplotlib.pyplot as plt


def grph_data(with_f, without):
    y = ([0], [0])

    for file, idx in ((with_f, 0), (without, 1)):
        print(file, idx)
        with open(file, 'r') as f:
            for line in f:
                split = line.strip('\n').split(',')

                cum_routes = int(split[3].strip())

                if cum_routes > 0:
                    y[idx].append(cum_routes)
    return y


def main():
    path = "/home/thomas/Documents/BGP_perf/filter_rib/"

    ys = grph_data(path + 'prefixes.filter', path + 'prefixes.nofilter')

    total = 200_000

    a = ys[0][8] / total

    plt.plot([i / total for i in ys[0][0:9]], label="Filter enabled")
    plt.plot([i / total for i in ys[1][0:9]], label="Filter disabled")

    plt.yticks(list(plt.yticks()[0]) + [a])

    plt.ylabel("Cumulated RIB entries")
    plt.xlabel("Measurement point")
    plt.legend()
    plt.grid()
    plt.show()


def main2(with_f, without):
    y = ([], [])

    for file, idx in ((with_f, 0), (without, 1)):
        with open(file, 'r') as f:
            curr_ref = -1
            for line in f:
                data = json.loads(line)

                if curr_ref == -1:
                    curr_ref = data['time']

                real_time = (data['time'] - curr_ref) / (10 ** 9)
                mem_point = data['info']['memory_full_info'][0]

                if idx == 0:
                    if 604.338 <= real_time <= 608.05:
                        y[idx].append({'time': real_time - 604.338, 'mem': mem_point})
                else:
                    if 587.33 <= real_time <= 591.1:
                        y[idx].append({'time': real_time - 587.33, 'mem': mem_point})

    x1 = [(i['time']) for i in y[0]]
    y1 = [i['mem'] / (10 ** 6) for i in y[0]]

    x2 = [(i['time']) for i in y[1]]
    y2 = [i['mem'] / (10 ** 6) for i in y[1]]

    fig, ax = plt.subplots()

    ax.plot(x1, y1, label="Filter enabled")
    ax.plot(x2, y2, label="Filter disabled")

    plt.xlabel("Time (s)")
    plt.ylabel("Memory Consumption (MB)")

    plt.legend()
    plt.grid()
    plt.show()


if __name__ == '__main__':
    path = "/home/thomas/Documents/BGP_perf/filter_rib/"

    with_f = path + "out.res.perf01"
    without = path + "out.res.perf_not_filter"

    main2(with_f, without)

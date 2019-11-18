import matplotlib.pyplot as plt
import json


def analyse(file):
    start = -1

    prefixes = set()

    data = []
    reversed_data = []
    final = []

    with open(file, 'r') as f:
        for line in f:
            sample = json.loads(line)

            if start == -1:
                start = sample['time']

            data.append({
                'time': (sample['time'] - start) / (10 ** 6),
                'type': sample['type'],
            })

    return [i['time'] for i in data]


def ploplot2():
    x_dec_proc_no, x_dec_proc = analyse('./new_data/recv_data_no_plugins.txt'), analyse(
        './new_data/recv_data_full_decision_process.txt')

    total = len(x_dec_proc_no)

    y1 = [(i / total) * 100 for i in range(1, len(x_dec_proc_no) + 1)]
    y2 = [(i / total) * 100 for i in range(1, len(x_dec_proc) + 1)]

    plt.plot(x_dec_proc_no, y1, linestyle='dashdot', label='Decision Process Without Plugins')
    plt.plot(x_dec_proc, y2, label='Decision Process Fully Pluginized')
    plt.ylabel('Processed Routes (%)')
    plt.xlabel('Time (seconds)')
    plt.legend()
    plt.grid()
    plt.show()


def ploplot():
    x_nothing, x2_filter = analyse('./recv_data.noasfilter'), analyse('./recv_data.asfilter')
    x3_reduce, x4_decproc = analyse('./recv_data.reduce_filter'), analyse('./recv_data.dec_proc')
    x5_monit, x6_decproc_no = analyse('./recv_data.monit'), analyse('./recv_data.no_plug_decproc')

    total = len(x_nothing)

    y = [i / total for i in range(1, len(x_nothing) + 1)]
    y2 = [i / total for i in range(1, len(x2_filter) + 1)]
    y3 = [i / total for i in range(1, len(x3_reduce) + 1)]
    y5 = [i / total for i in range(1, len(x5_monit) + 1)]

    plt.plot(x_nothing, y, linestyle='dashdot', label='Without plugins')
    # plt.plot(x2_filter, y2, label='With filter : Select routes from odd ASes')
    # plt.plot(x3_reduce, y3, label='With filter : Limit redundant routes')
    plt.plot(x5_monit, y5, label='Monitor activated')
    plt.ylabel('Processed Routes (%)')
    plt.xlabel('Time (seconds)')
    plt.legend()
    plt.grid()
    plt.show()


def ploplot_base():
    x_nothing = analyse('./recv_data.noasfilter')
    total = len(x_nothing)

    y = [i / total for i in range(1, len(x_nothing) + 1)]
    plt.plot(x_nothing, y, linestyle='dashdot', label='Without plugins')
    plt.ylabel('Processed Routes (%)')
    plt.xlabel('Time (seconds)')
    plt.legend()
    plt.grid()
    plt.show()


def ploplot_base2():
    x6_decproc_no = analyse('./recv_data.no_plug_decproc')
    total = len(x6_decproc_no)

    y = [i / total for i in range(1, len(x6_decproc_no) + 1)]
    plt.plot(x6_decproc_no, y, linestyle='dashdot', label='Decision Process Without Plugins')
    plt.ylabel('Processed Routes (%)')
    plt.xlabel('Time (seconds)')
    plt.legend()
    plt.grid()
    plt.show()


if __name__ == '__main__':
    # ploplot_base2()
    # ploplot_base()
    # ploplot()
    ploplot2()

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import json


def exec_time(file):
    time = []

    with open(file, 'r') as f:
        for line in f:
            a = json.loads(line)
            time.append(a['time'] / (10 ** 9))

    return time


def multiple(a, b):
    x_pos_a = [i['pos'] for i in a]
    x_labels_a = [i['label'] for i in a]
    y_data_a = [exec_time(i['path']) for i in a]

    x_pos_b = [i['pos'] for i in b]
    x_labels_b = [i['label'] for i in b]
    y_data_b = [exec_time(i['path']) for i in b]

    mdr = ["Vanilla (Left) +\nuBPF inserted (no plugins)\n(Right)", "1 Plugin\nDecision",
           "5 Plugins\nDecision", "Decision\nAll", "Every\nUse Cases", ""]

    a = plt.boxplot(y_data_a, labels=mdr, showfliers=False, positions=x_pos_a, patch_artist=True,
                    boxprops=dict(alpha=.3))
    b = plt.boxplot(y_data_b, labels=['' for _ in range(len(x_labels_b))], showfliers=False, positions=x_pos_b,
                    patch_artist=True, boxprops=dict(alpha=.5))

    for patchb in b['boxes']:
        patchb.set_facecolor('pink')

    for patcha in a['boxes']:
        patcha.set_facecolor('lightgrey', )

    red_patch = mpatches.Patch(color='pink', label='Interpreted')
    blue_patch = mpatches.Patch(color='lightgrey', label='JIT')

    plt.legend(handles=[red_patch, blue_patch])

    plt.ylabel('Execution Time (seconds)')
    plt.xticks([1.25, 2.75, 4.25, 5.75, 7.25])


    plt.grid()

    plt.show()


def boxplot(dic_file):
    x_pos = [i['pos'] for i in dic_file]
    x_labels = [i['label'] for i in dic_file]
    y_data = [exec_time(i['path']) for i in dic_file]

    plt.boxplot(y_data, labels=x_labels, showfliers=False, positions=x_pos)

    plt.grid()
    plt.show()


def main():
    multiple([
        {'label': 'Vanilla\nBGP', 'path': './vanilla', 'pos': 1},
        {'label': 'BGP\nuBPF ON\n(0 plugins)', 'path': './noplug', 'pos': 1.5},
        {'label': '1 plugin\ndecision', 'path': './1decplug', 'pos': 2.5},
        {'label': '5 plugins\ndecision', 'path': './5decplug', 'pos': 4},
        {'label': 'Decision\nall', 'path': './decall', 'pos': 5.5},
        {'label': 'All', 'path': './all', 'pos': 7},

    ], [
        {'label': '1 plugin\ndecision\n(INT)', 'path': './1decplugnojit', 'pos': 3},
        {'label': '5 plugins\ndecision\n(INT)', 'path': './5decplugnojit', 'pos': 4.5},
        {'label': 'Decision\nall\n(INT)', 'path': './decallnojit', 'pos': 6},
        {'label': 'All\n(INT)', 'path': './allnojit', 'pos': 7.5},
    ])

    boxplot([
        {'label': 'Vanilla\nBGP', 'path': './vanilla', 'pos': 1},
        {'label': 'BGP\nuBPF ON\n(0 plugins)', 'path': './noplug', 'pos': 2},
        {'label': '1 plugin\ndecision\n(JIT)', 'path': './1decplug', 'pos': 3},
        {'label': '1 plugin\ndecision\n(INT)', 'path': './1decplugnojit', 'pos': 4},
        {'label': '5 plugins\ndecision\n(JIT)', 'path': './5decplug', 'pos': 5},
        {'label': '5 plugins\ndecision\n(INT)', 'path': './5decplugnojit', 'pos': 6},
        {'label': 'Decision\nall\n(JIT)', 'path': './decall', 'pos': 7},
        {'label': 'Decision\nall\n(INT)', 'path': './decallnojit', 'pos': 8},
        {'label': 'All\n(JIT)', 'path': './all', 'pos': 9},
        {'label': 'All\n(INT)', 'path': './allnojit', 'pos': 10},
    ])

    boxplot([
        {'label': 'Vanilla\nBGP', 'path': './vanilla', 'pos': 1},
        {'label': 'BGP\nuBPF ON\n(0 plugins)', 'path': './noplug', 'pos': 2},
        {'label': '1 plugin\ndecision', 'path': './1decplug', 'pos': 3},
        {'label': '5 plugins\ndecision', 'path': './5decplug', 'pos': 4},
        {'label': 'Decision\nall', 'path': './decall', 'pos': 5},
        {'label': 'All', 'path': './all', 'pos': 6},
    ])

    boxplot([
        {'label': 'Vanilla\nBGP', 'path': './vanilla', 'pos': 1},
        {'label': 'BGP\nuBPF ON\n(0 plugins)', 'path': './noplug', 'pos': 2},
        {'label': '1 plugin\ndecision', 'path': './1decplugnojit', 'pos': 3},
        {'label': '5 plugin\ndecision', 'path': './5decplugnojit', 'pos': 4},
        {'label': 'Decision\nall', 'path': './decallnojit', 'pos': 5},
        {'label': 'All', 'path': './allnojit', 'pos': 6},
    ])


if __name__ == '__main__':
    main()

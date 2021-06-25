import csv
import pathlib
import json

import matplotlib.pyplot as plt

from ast import literal_eval


# cbmc stuff
def read_csv(csv_path):
    data = dict()
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)

        for row in reader:
            name = row['name']
            if name not in data:
                data[name] = list()
            data[name].append(float(row['realtime']))

    return data


# cbmc stuff
def plot(data):
    x_name = list()
    ys = list()

    for key in data:
        x_name.append(key)
        ys.append(data[key])

    fig, ax = plt.subplots()
    ax.boxplot(ys,
               labels=x_name)

    ax.set_ylabel("Execution Time (s)")

    plt.show()


# T2 stuff
def recollect_t2_data_and_plot(data_dir, glob):
    folder = pathlib.Path(data_dir)

    data = dict()

    if not folder.is_dir():
        raise FileNotFoundError(f"{folder} directory not found")

    for file in folder.glob(glob):
        with file.open(mode='r') as f:
            for line in f:
                try:
                    current_measure = literal_eval(line)
                except SyntaxError:
                    continue

                plugin = current_measure['path']

                if plugin not in data:
                    data[plugin] = list()
                data[plugin].append(current_measure['time'])

    x_name = [key for key in data]
    ys = [data[key] for key in data]

    fig, ax = plt.subplots()
    ax.boxplot(ys,
               labels=x_name)

    ax.set_ylabel("Execution Time (s)")

    plt.show()


if __name__ == '__main__':
    doneeey = read_csv("/home/thomas/Documents/GitHub/ubpf_tools/misc/experiments/data/seahorn_exec_time.csv")
    plot(doneeey)
    # recollect_t2_data_and_plot("/tmp", "*_out.txt")

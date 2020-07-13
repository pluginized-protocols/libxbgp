import json
from ipaddress import ip_network
import matplotlib.pyplot as plt


def get_info(path):
    the_dict = dict()

    with open(path, "r") as f:
        for line in f:
            a = json.loads(line.strip())

            if a['message_type_string'] == "UPDATE":
                for nlri in a['message_data']['nlri']:

                    try:
                        the_net = ip_network(nlri)
                        if the_net not in the_dict:  # capture the first occurrence of the nlri
                            the_dict[the_net] = list()
                        the_dict[the_net].append(float(a['timestamp']))
                    except ValueError:
                        pass

    return the_dict


def final_time(from_router, to_router):
    final_time_data = dict()

    for key in from_router:
        if key in to_router:
            final_time_data[key] = abs(to_router[key][-1] - from_router[key][0])

    return final_time_data


def plot_time_per_prefixes(time_per_prefixes_by_proto):
    fig, axs = plt.subplots(len(time_per_prefixes_by_proto))
    curr_proto = -1
    for proto_key in time_per_prefixes_by_proto:
        curr_proto += 1
        time_x_arr = []
        labels = []

        for time_x, label in time_per_prefixes_by_proto[proto_key]:
            tmp_tx = [time_x[a] for a in time_x]
            time_x_arr.append(tmp_tx)
            labels.append(label)

            print(min(tmp_tx), max(tmp_tx))
            print("Nb_Prefixes %d" % len(tmp_tx))

        axs[curr_proto].hist(time_x_arr, 4000, cumulative=True, histtype='step',
                             density=True, label=labels)

        axs[curr_proto].grid(True)
        axs[curr_proto].set_title(proto_key)
        axs[curr_proto].set_xlabel('Time (s)')
        axs[curr_proto].set_ylabel('CDF')
        axs[curr_proto].legend(loc='lower right')

    plt.tight_layout()
    plt.show()


def main(results):
    array_time = dict()

    for proto_name in results:
        for f, to, label in results[proto_name]:
            time_per_pfx = final_time(get_info(f), get_info(to))

            if proto_name not in array_time:
                array_time[proto_name] = list()

            array_time[proto_name].append((time_per_pfx, label))

    plot_time_per_prefixes(array_time)


if __name__ == '__main__':
    main({
        "Bird": [
            ("/tmp/injector_plugin_bird.json", "/tmp/plugin_monitor_bird.json", "No Plugins"),
            ("/tmp/injector_plugin_rpki_bird.json", "/tmp/plugin_monitor_rpki_bird.json", "RPKI Enabled")
        ],
        "FRRouting": [
            ("/tmp/injector_plugin_frr.json", "/tmp/plugin_monitor_frr.json", "No Plugins"),
            ("/tmp/injector_plugin_rpki_frr.json", "/tmp/plugin_monitor_rpki_frr.json", "RPKI Enabled")
        ]
    })

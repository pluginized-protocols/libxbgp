import statistics

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib

matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42


# rc('font', **{'family': 'sans-serif', 'sans-serif': ['Helvetica']})
# for Palatino and other serif fonts use:
# rc('font',**{'family':'serif','serif':['Palatino']})
# rc('text', usetex=True)


def get_timecode(from_trace, to_trace):
    end_update = -1
    begin_update = -1

    for line in from_trace:
        a = line.strip()
        begin_update = float(a)
        break

    for line in to_trace:
        a = line.strip()
        end_update = float(a)

    assert end_update != -1 and begin_update != -1

    return end_update - begin_update


def get_data_trace(zipped_trace):
    times = list()
    for from_trace, to_trace in zipped_trace:
        with open(from_trace, 'r') as from_f, open(to_trace, 'r') as to_trace_f:
            times.append(get_timecode(from_f, to_trace_f))
    return times


def main(args):
    data = []

    for rib_size in args:
        for proto in args[rib_size]:

            for expe_one, expe_two in args[rib_size][proto]:

                zipped_trace_one, expe_kind_one, native_one = expe_one
                zipped_trace_two, expe_kind_two, native_two = expe_two

                times_one = get_data_trace(zipped_trace_one)
                times_two = get_data_trace(zipped_trace_two)

                if native_one:
                    med = statistics.median(times_one)

                    for the_time in times_two:
                        data.append((rib_size, proto, expe_kind_two, (((the_time * 1.0) / med) - 1) * 100))

                else:
                    med = statistics.median(times_two)
                    for the_time in times_one:
                        data.append((rib_size, proto, expe_kind_one, (((the_time * 1.0) / med) - 1) * 100))

    fg = pd.DataFrame({
        'Implementation Under Test (724k routes)': [a[1] for a in data],
        'Test Type': ["%s" % a[2] for a in data],
        'Relative Performance Impact (%)': [a[3] for a in data]
    }).pipe(
        (sns.catplot, 'data'),
        x='Implementation Under Test (724k routes)', y='Relative Performance Impact (%)', hue="Test Type",
        kind='box', legend=False  # or boxen
    )

    plt.axhline(linewidth=2, color='k')

    plt.grid(True)
    plt.legend(loc='lower right')
    plt.show()


if __name__ == '__main__':
    main_folder = "/home/thomas/Documents/trace_bgp"

    list_args = {
        724000: {
            "$x$FRRouting": [
                ((zip(["%s/rr_tests/724k_routes/process_trace/injector_test_frr_%d.json" % (main_folder, i) for i in
                       range(1, 16)],
                      ["%s/rr_tests/724k_routes/process_trace/test_monitor_frr_%d.json" % (main_folder, i) for i in
                       range(1, 16)]),
                  "Route Reflectors", True),
                 (zip(["%s/rr_tests/724k_routes/process_trace/injector_test_rr_frr_%d.json" % (main_folder, i) for i in
                       range(1, 16)],
                      ["%s/rr_tests/724k_routes/process_trace/test_monitor_rr_frr_%d.json" % (main_folder, i) for i in
                       range(1, 16)]),
                  "Route Reflectors", False)),
                (
                    (zip(["%s/rpki_tests/724k_routes_tests/process_trace/injector_test_frr_%d.json" % (main_folder, i)
                          for i
                          in range(1, 16)],
                         ["%s/rpki_tests/724k_routes_tests/process_trace/test_monitor_frr_%d.json" % (main_folder, i)
                          for i
                          in range(1, 16)]),
                     "Origin Validation", True),
                    (zip(
                        ["%s/rpki_tests/724k_routes_tests/process_trace/injector_test_rpki_frr_%d.json" % (
                        main_folder, i)
                         for
                         i in range(1, 16)],
                        ["%s/rpki_tests/724k_routes_tests/process_trace/test_monitor_rpki_frr_%d.json" % (
                        main_folder, i)
                         for
                         i in range(1, 16)]),
                     "Origin Validation", False)),
            ],
            "$x$BIRD": [
                ((zip(["%s/rr_tests/724k_routes/process_trace/injector_test_bird_%d.json" % (main_folder, i) for i in
                       range(1, 16)],
                      ["%s/rr_tests/724k_routes/process_trace/test_monitor_bird_%d.json" % (main_folder, i) for i in
                       range(1, 16)]),
                  "Route Reflectors", True),
                 (zip(["%s/rr_tests/724k_routes/process_trace/injector_test_rr_bird_%d.json" % (main_folder, i) for i in
                       range(1, 16)],
                      ["%s/rr_tests/724k_routes/process_trace/test_monitor_rr_bird_%d.json" % (main_folder, i) for i in
                       range(1, 16)]),
                  "Route Reflectors", False)),
                ((zip(
                    ["%s/rpki_tests/724k_routes_tests/process_trace/injector_test_bird_%d.json" % (main_folder, i) for i
                     in range(1, 16)],
                    ["%s/rpki_tests/724k_routes_tests/process_trace/test_monitor_bird_%d.json" % (main_folder, i) for i
                     in range(1, 16)]),
                  "Origin Validation", True),
                 (zip(
                     ["%s/rpki_tests/724k_routes_tests/process_trace/injector_test_rpki_bird_%d.json" % (main_folder, i)
                      for
                      i in range(1, 16)],
                     ["%s/rpki_tests/724k_routes_tests/process_trace/test_monitor_rpki_bird_%d.json" % (main_folder, i)
                      for
                      i in range(1, 16)]),
                  "Origin Validation", False)),
            ]
        }
    }

    main(list_args)


def lol():
    list_args = {
        200000: {
            "$x$FRRouting": [
                (zip(["%s/200k_routes_tests/process_trace/injector_test_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/200k_routes_tests/process_trace/test_monitor_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "No Extensions"),
                (zip(["%s/200k_routes_tests/process_trace/injector_test_rpki_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/200k_routes_tests/process_trace/test_monitor_rpki_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "Origin Validation Enabled")
            ],
            "$x$BIRD": [
                (zip(["%s/200k_routes_tests/process_trace/injector_test_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/200k_routes_tests/process_trace/test_monitor_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "No Extensions"),
                (zip(["%s/200k_routes_tests/process_trace/injector_test_rpki_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/200k_routes_tests/process_trace/test_monitor_rpki_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "Origin Validation Enabled")
            ]
        },
        400000: {
            "$x$FRRouting": [
                (zip(["%s/400k_routes_tests/process_trace/injector_test_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/400k_routes_tests/process_trace/test_monitor_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "No Extensions"),
                (zip(["%s/400k_routes_tests/process_trace/injector_test_rpki_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/400k_routes_tests/process_trace/test_monitor_rpki_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "Origin Validation Enabled")
            ],
            "$x$BIRD": [
                (zip(["%s/400k_routes_tests/process_trace/injector_test_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/400k_routes_tests/process_trace/test_monitor_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "No Extensions"),
                (zip(["%s/400k_routes_tests/process_trace/injector_test_rpki_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/400k_routes_tests/process_trace/test_monitor_rpki_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "Origin Validation Enabled")
            ]
        },
        800000: {
            "$x$FRRouting": [
                (zip(["%s/800k_routes_tests/process_trace/injector_test_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/800k_routes_tests/process_trace/test_monitor_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "No Extensions"),
                (zip(["%s/800k_routes_tests/process_trace/injector_test_rpki_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/800k_routes_tests/process_trace/test_monitor_rpki_frr_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "Origin Validation Enabled")
            ],
            "$x$BIRD": [
                (zip(["%s/800k_routes_tests/process_trace/injector_test_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/800k_routes_tests/process_trace/test_monitor_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "No Extensions"),
                (zip(["%s/800k_routes_tests/process_trace/injector_test_rpki_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)],
                     ["%s/800k_routes_tests/process_trace/test_monitor_rpki_bird_%d.json" % (main_folder, i) for i in
                      range(1, 16)]),
                 "Origin Validation Enabled")
            ]
        }
    }


def main_oldiodl(args):
    data = []

    for rib_size in args:
        for proto in args[rib_size]:

            for expe_one, expe_two in args[rib_size][proto]:

                zipped_trace_one, expe_kind_one, native_one = expe_one
                zipped_trace_two, expe_kind_two, native_two = expe_two

                times_one = get_data_trace(zipped_trace_one)
                times_two = get_data_trace(zipped_trace_two)

                if native_one:
                    med = statistics.median(times_one)

                    for the_time in times_two:
                        data.append((rib_size, proto, expe_kind_two, (((the_time * 1.0) / med) - 1) * 100))

                else:
                    med = statistics.median(times_two)
                    for the_time in times_one:
                        data.append((rib_size, proto, expe_kind_one, (((the_time * 1.0) / med) - 1) * 100))

    fg = pd.DataFrame({
        'RIB Size': [a[0] for a in data],
        'Test Type': ["%s (%s)" % (a[2], a[1]) for a in data],
        'Relative Performance Impact (%)': [a[3] for a in data]
    }).pipe(
        (sns.catplot, 'data'),
        x='RIB Size', y='Relative Performance Impact (%)', hue="Test Type",
        kind='box', legend=False  # or boxen
    )

    plt.axhline(linewidth=2, color='k')

    plt.grid(True)
    plt.legend(loc='lower right')
    plt.show()

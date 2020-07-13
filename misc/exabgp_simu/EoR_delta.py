import json


def main(paths):
    for path in paths:
        eor_frames = json.load(path)

        epoch_times = list()

        for eor_frame in eor_frames:
            epoch_times.append(eor_frame['_source']['layers']['frame']['frame.time_epoch'])


if __name__ == '__main__':
    main("/tmp/sdfff")

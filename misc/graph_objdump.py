import json
import matplotlib.pyplot as plt


def main():
    with open('./analyse', 'r') as f:
        data = json.load(f)

    barWidth = 0.9

    x1 = [i for i in range(len(data))]
    y1 = [i['external_call'] for i in data]
    y2 = [i['size'] for i in data]
    y3 = [i['code'] for i in data]
    y4 = [i['instructions'] for i in data]

    f, axarr = plt.subplots(2, 2)

    # axarr[0, 0].bar(x1, y1, color='b', width=barWidth, edgecolor='white', label='var1')
    axarr[0, 0].hist(y1, 75, density=True, histtype='step', cumulative=True, alpha=0.75)
    axarr[0, 0].set_title('# external calls')
    axarr[0, 0].grid()
    # axarr[0, 1].bar(x1, y2, color='r', width=barWidth, edgecolor='white', label='var2')
    axarr[0, 1].hist(y2, 75, density=True, histtype='step', cumulative=True, alpha=0.75)
    axarr[0, 1].set_title('ELF Size (bytes)')
    axarr[0, 1].grid()
    # axarr[1, 0].bar(x1, y3, color='g', width=barWidth, edgecolor='white', label='var3')
    axarr[1, 0].hist(y3, 75, density=True, histtype='step', cumulative=True, alpha=0.75)
    axarr[1, 0].set_title('Lines of code')
    axarr[1, 0].grid()
    # axarr[1, 1].bar(x1, y4, color='orange', width=barWidth, edgecolor='white', label='var4')
    axarr[1, 1].hist(y4, 75, density=True, histtype='step', cumulative=True, alpha=0.75)
    axarr[1, 1].set_title('# eBPF instructions')
    axarr[1, 1].grid()

    f.subplots_adjust(hspace=0.3)

    plt.show()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3

import argparse
from typing import Dict
import matplotlib.pyplot as plt
import os
import datetime

from metric import METRIC

class LinePlot():
    def __init__(self) -> None:
        pass

    def _read_metrics(self, data_dir: str, subdir: str) -> Dict[str, str]:
        with open(os.path.join(data_dir, subdir, 'metric.log')) as file:
            lines = file.readlines()

        ret = {}
        for line in lines:
            name, value = line.split(':')
            _, field = name.split('.', 1)
            val, _ = value.split('|', 1)

            if field not in ret:
                ret[field] = []

            ret[field].append(float(val))

        return ret

    def _read_data(self, data_dir: str) -> Dict[str, Dict[str, str]]:
        dirs = os.listdir(data_dir)
        data = {
            i:self._read_metrics(data_dir, i)
                for i in dirs
        }

        return data

    def _filter_metric(self, data, metric: str):
        return {
            index:instance[metric] for index, instance in data.items()
        }

    def _prepare_data(self, metric: str, data_dir: str):
        return self._filter_metric(self._read_data(data_dir), metric)

    def plot(self, metric: str, data_dir: str, time: float, ticks: int):
        cfg = METRIC[metric]
        data = self._prepare_data(cfg.metric, data_dir)
        maxticks = max(len(Y) for _, Y in data.items())
        xticks = range(0, maxticks, maxticks // ticks)
        labels = [ datetime.timedelta(seconds=time * i / len(xticks)) for i in range(0, len(xticks)) ]
        print(xticks, labels)
        plt.xticks(xticks, labels, rotation=45)
        plt.xlabel("Time in hours:minutes:seconds")
        plt.ylabel(cfg.ylabel)
        plt.title(data_dir.replace(".", "").replace("/", ""))
        plt.tight_layout()


        for _, Y in data.items():
            plt.plot(Y)

def main():
    parser = argparse.ArgumentParser("Line plot")
    parser.add_argument('metric_dir', type=str, help="Directory with metrics to read")
    parser.add_argument('--metric', choices=METRIC.keys(), help="Metric to plot")
    parser.add_argument('--total-time', type=float, help="Total execution time")
    parser.add_argument('--ticks', default=10, type=int, help="Number of ticks on xaxis")
    parser.add_argument('--save', required=False, type=str, help="Save figure to file")
    parser.add_argument('--show', required=False, action='store_true', help="Show the generated figure")
    args = parser.parse_args()

    plot = LinePlot()
    plot.plot(args.metric, args.metric_dir, args.total_time, args.ticks)

    if args.save is not None:
        plt.savefig(args.save)

    if args.show:
        plt.show()


if __name__ == "__main__":
    main()

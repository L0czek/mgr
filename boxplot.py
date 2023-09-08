#!/usr/bin/env python3

import argparse
from functools import reduce
from typing import Dict, List
from urllib import request
import matplotlib.pyplot as plt
import os
import datetime

from metric import METRIC

class BoxPlot():
    def __init__(self) -> None:
        pass

    def _read_metrics(self, data_dir: str, subdir: str) -> Dict[str, List[float]]:
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

    def _join_data(self, data):
        return reduce(lambda a, b: a + b, data.values())

    def plot(self, metric: str, data_dirs: List[str]):
        cfg = METRIC[metric]
        data = {
            dirname:self._join_data(self._prepare_data(cfg.metric, dirname))
                for dirname in data_dirs
        }

        plt.boxplot(data.values(), labels=data.keys())
        plt.xticks(rotation=45)
        plt.title(cfg.title)
        plt.ylabel(cfg.ylabel)
        plt.tight_layout()

def main():
    parser = argparse.ArgumentParser("Line plot")
    parser.add_argument('metric_dirs', type=str, help="Directories with metrics to read", nargs='+')
    parser.add_argument('--metric', choices=METRIC.keys(), help="Metric to plot")
    parser.add_argument('--save', required=False, type=str, help="Save figure to file")
    parser.add_argument('--show', required=False, action='store_true', help="Show the generated figure")
    args = parser.parse_args()

    plot = BoxPlot()
    plot.plot(args.metric, data_dirs=args.metric_dirs)

    if args.save is not None:
        plt.savefig(args.save)

    if args.show:
        plt.show()


if __name__ == "__main__":
    main()

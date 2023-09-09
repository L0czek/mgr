#!/usr/bin/env python3

from asyncio.taskgroups import TaskGroup
from dataclasses import asdict, dataclass
from copy import deepcopy
import socket
import os
import glob
import logging
import aioshutil
import asyncio
import aiofiles
import aiofiles.os
import argparse
from tqdm import tqdm
from run import run_fuzzer
from multiprocessing import Process, Pipe
import select

@dataclass()
class FuzzerConfig:
    afl_debug_log: bool = True
    fuzzer_debug_log: bool = True
    qemu_log_file: str = 'qemu.log'
    afl_log_file: str = 'afl.log'
    execsrv_log_file: str = 'srv.log'
    enable_statsd: bool = True
    statsd_host: str = "127.0.0.1:8125"
    launch_terminals: bool = False
    stdio_normal_port: int = 54320
    stdio_secure_port: int = 54321
    afl_dir: str = 'optee/AFLplusplus/'
    qemu_dir: str = 'optee/qemu/build/'
    execsrv_dir: str = './execsrv/build'
    optee_out_dir: str = './optee/out/bin/'
    optee_build_dir: str = './optee/build/'
    exit: bool = True
    command: str = 'fuzzer'
    normal: bool = False
    fast: bool = False
    norevert: bool = False
    tznorevert: bool = False
    skip_cpu_check: bool = True
    tmpfs: str = './tmpfs'
    timeout: float = 50000
    input: str = './in'
    output: str = './out'
    noout: bool = True
    testcase_decoding_mode: str = 'dsl'
    no_affinity: bool = True # This is required to work, just says how shitty this setup is

    def prepare(self, index: int, subdir: str):
        cfg = deepcopy(self)

        DIR = os.path.dirname(__file__)
        cfg.afl_dir = os.path.join(DIR, self.afl_dir)
        cfg.qemu_dir = os.path.join(DIR, self.qemu_dir)
        cfg.execsrv_dir = os.path.join(DIR, self.execsrv_dir)
        cfg.optee_out_dir = os.path.join(DIR, self.optee_out_dir)
        cfg.optee_build_dir = os.path.join(DIR, self.optee_build_dir)
        cfg.tmpfs = os.path.join(DIR, self.tmpfs)

        cfg.input = os.path.join(DIR, subdir, cfg.input)
        cfg.output= os.path.join(DIR, subdir, cfg.output)
        cfg.qemu_log_file = os.path.join(DIR, subdir, cfg.qemu_log_file)
        cfg.afl_log_file = os.path.join(DIR, subdir, cfg.afl_log_file)
        cfg.execsrv_log_file = os.path.join(DIR, subdir, cfg.execsrv_log_file)

        cfg.stdio_normal_port += index * 2
        cfg.stdio_secure_port += index * 2

        host, port = cfg.statsd_host.split(":")
        cfg.statsd_host = f"{host}:{int(port) + index}"

        return cfg

class TCPDumper():
    def __init__(self, port: int, filename: str) -> None:
        self.port = port
        self.filename = filename

    def dump(self, shutdown_pipe):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', self.port))
        sock.listen()
        client, _ = sock.accept()

        with open(self.filename, 'wb') as file:
            while True:
                rlist, _, _ = select.select([client, shutdown_pipe], [], [])

                for fd in rlist:
                    if fd is client:
                        file.write(client.recv(0x1000))
                        file.flush()
                    else:
                        return

class UDPDumper():
    def __init__(self, port: int, filename: str) -> None:
        self.port = port
        self.filename = filename
    def dump(self, shutdown_pipe):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', self.port))

        with open(self.filename, 'wb') as file:
            while True:
                rlist, _, _ = select.select([sock, shutdown_pipe], [], [])

                for fd in rlist:
                    if fd is sock:
                        file.write(sock.recv(0x1000))
                        file.flush()
                    else:
                        return


class FuzzerInstance():
    def __init__(self, cfg: FuzzerConfig) -> None:
        self.cfg = cfg

    async def setup(self, index: int, subdir: str, corpusdir: str):
        self.cfg = self.cfg.prepare(index, subdir)

        DIR = os.path.dirname(__file__)
        os.mkdir(subdir)
        await aiofiles.os.makedirs(self.cfg.input)
        await aiofiles.os.makedirs(self.cfg.output)
        self.normal_log = os.path.join(DIR, subdir, 'normal.log')
        self.secure_log = os.path.join(DIR, subdir, 'secure.log')
        self.metric_log = os.path.join(DIR, subdir, 'metric.log')
        _, port = self.cfg.statsd_host.split(':')
        self.metric_dumper = UDPDumper(int(port), self.metric_log)
        self.normal_dumper = TCPDumper(self.cfg.stdio_normal_port, self.normal_log)
        self.secure_dumper = TCPDumper(self.cfg.stdio_secure_port, self.secure_log)

        for testcase in glob.glob(os.path.join(corpusdir, '*')):
            await aioshutil.copy(testcase, self.cfg.input)

    async def run(self, time: float):
        metric_log_a, metric_log_b = Pipe()
        metric_log = Process(target=self.metric_dumper.dump, args=(metric_log_b,))
        normal_log_a, normal_log_b = Pipe()
        normal_log = Process(target=self.normal_dumper.dump, args=(normal_log_b,))
        secure_log_a, secure_log_b = Pipe()
        secure_log = Process(target=self.secure_dumper.dump, args=(secure_log_b,))

        metric_log.start()
        normal_log.start()
        secure_log.start()
        process = run_fuzzer(argparse.Namespace(**asdict(self.cfg)))

        await asyncio.sleep(time)

        process.terminate()
        process.communicate()

        metric_log_a.send("DUPA")
        normal_log_a.send("DUPA")
        secure_log_a.send("DUPA")

        metric_log.join()
        normal_log.join()
        secure_log.join()

class Benchmark():
    def __init__(self, mode: str, benchmark_dir: str, corpus: str, decoding_mode: str):
        self.mode = mode
        self.benchmark_dir = benchmark_dir
        self.corpus = corpus

        self.cfg = FuzzerConfig()

        if mode == 'normal':
            self.cfg.normal = True
        elif mode == 'fast':
            self.cfg.fast = True
        elif mode == 'norevert':
            self.cfg.norevert = True
        elif mode == "tznorevert":
            self.cfg.tznorevert = True

        self.cfg.testcase_decoding_mode = decoding_mode

    async def run_for(self, threads: int, time: float, progress: bool):
        instances = [ FuzzerInstance(self.cfg) for _ in range(threads) ]

        for index, inst in enumerate(tqdm(instances)):
            await inst.setup(index, os.path.join(self.benchmark_dir, str(index)), self.corpus)

        async with TaskGroup() as tg:
            futures = [ asyncio.create_task(inst.run(time)) for inst in instances ]

            for _ in tqdm(range(int(time))):
                await asyncio.sleep(1)

            asyncio.gather(*futures)

async def main():
    parser = argparse.ArgumentParser("benchmark")
    parser.add_argument('--mode', type=str, choices=['normal', 'fast', 'norevert', 'tznorevert'], help="Select fuzzing mode")
    parser.add_argument('--threads', type=int, default=1, help="Instances to run concurrently")
    parser.add_argument('--dir', type=str, default='benchmarks', help="Directory to store benchmark logs")
    parser.add_argument('--time', type=float, default=3600 * 2, help="Run for n seconds")
    parser.add_argument('--corpus', type=str, help="Coprus directory")
    parser.add_argument('--testcase-decoding-mode', type=str, choices=['dsl', 'direct'], default='dsl', help="Test case decoding mode")
    parser.add_argument('--progress', required=False, action='store_true', help="Show progress bar")

    args = parser.parse_args()

    if os.path.isdir(args.dir):
        await aioshutil.rmtree(args.dir)
    await aiofiles.os.makedirs(args.dir)
    benchmark = Benchmark(args.mode, args.dir, args.corpus, args.testcase_decoding_mode)
    await benchmark.run_for(args.threads, args.time, args.progress)

if __name__ == "__main__":
    logging.getLogger("asyncio")
    asyncio.run(main())

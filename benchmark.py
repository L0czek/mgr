#!/usr/bin/env python3

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

        print(cfg)
        return cfg


class FuzzerInstance():
    def __init__(self, cfg: FuzzerConfig) -> None:
        self.cfg = cfg

    async def setup(self, index: int, subdir: str, corpusdir: str):
        self.cfg = self.cfg.prepare(index, subdir)
        self.metric_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.metric_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.metric_socket.setblocking(False)
        host, port = self.cfg.statsd_host.split(':')
        self.metric_socket.bind((host, int(port)))

        self.normal_socket_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.normal_socket_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.normal_socket_srv.setblocking(False)
        self.normal_socket_srv.bind(('127.0.0.1', self.cfg.stdio_normal_port))
        self.normal_socket_srv.listen()

        self.secure_socket_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.secure_socket_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.secure_socket_srv.setblocking(False)
        self.secure_socket_srv.bind(('127.0.0.1', self.cfg.stdio_secure_port))
        self.secure_socket_srv.listen()

        DIR = os.path.dirname(__file__)
        os.mkdir(subdir)
        await aiofiles.os.makedirs(self.cfg.input)
        await aiofiles.os.makedirs(self.cfg.output)
        self.normal_log = os.path.join(DIR, subdir, 'normal.log')
        self.secure_log = os.path.join(DIR, subdir, 'secure.log')
        self.metric_log = os.path.join(DIR, subdir, 'metric.log')


        for testcase in glob.glob(os.path.join(corpusdir, '*')):
            await aioshutil.copy(testcase, self.cfg.input)

    async def dump_tcp(self, sock: socket.socket, path: str):
        try:
            loop = asyncio.get_event_loop()
            client, _ = await loop.sock_accept(sock)
            client.setblocking(False)
            await self.socket_to_file(client, path)
        except:
            pass

    async def dump_udp(self, sock: socket.socket, path: str):
        try:
            await self.socket_to_file(sock, path)
        except:
            pass

    async def socket_to_file(self, sock: socket.socket, path: str):
        loop = asyncio.get_event_loop()
        async with aiofiles.open(path, 'wb') as file:
            while True:
                data = await loop.sock_recv(sock, 0x1000)
                await file.write(data)

    async def run(self, time: float):
        async with asyncio.TaskGroup() as tg:
            _normal_stdio = asyncio.create_task(self.dump_tcp(self.normal_socket_srv, self.normal_log))
            _secure_stdio = asyncio.create_task(self.dump_tcp(self.secure_socket_srv, self.secure_log))
            _metric_io = asyncio.create_task(self.dump_udp(self.metric_socket, self.metric_log))
            process = run_fuzzer(argparse.Namespace(**asdict(self.cfg)))

            await asyncio.sleep(time)

            process.terminate()
            process.communicate()

    async def finish(self):
        self.normal_socket_srv.close()
        self.secure_socket_srv.close()
        self.metric_socket.close()

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
        logging.info("run_for")
        instances = []
        for n in range(threads):
            instances.append(asyncio.create_task(self.run_instance(n, time)))

        for _ in tqdm(range(int(time))):
            await asyncio.sleep(1)

        await asyncio.gather(*instances)

    async def run_instance(self, index: int, time: float):
        logging.info(f"Starting {index} fuzzer")
        instance = FuzzerInstance(self.cfg)
        await instance.setup(index, os.path.join(self.benchmark_dir, str(index)), self.corpus)

        try:
            await instance.run(time)
        except Exception as e:
            logging.error(f"Encountered exception while running fuzzer {index}: {e}")

        await instance.finish()

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

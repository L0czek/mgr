#!/usr/bin/env python3

import argparse
import os
import socket
import shlex
import time
import binascii
import ctypes
import ctypes.util
from subprocess import Popen, PIPE, check_call
from typing import Dict
from functools import partial
import uuid

DIR = os.path.dirname(__file__)

def parse_args():
    parser = argparse.ArgumentParser("Fuzzer runner")

    parser.add_argument('--afl-debug-log', required=False, action='store_true', help='More verbose output from AFL')
    parser.add_argument('--fuzzer-debug-log', required=False, action='store_true', help="More verbose log from QEMU")
    parser.add_argument('--qemu-log-file', required=False, type=str, help='Store logs from QEMU to file')
    parser.add_argument('--afl-log-file', required=False, type=str, help="Store logs from AFL to file")
    parser.add_argument('--execsrv-log-file', required=False, type=str, help="Store logs from execsrv to file")
    parser.add_argument('--enable-statsd', required=False, action='store_true', help="Send metrics to statsd server")
    parser.add_argument('--statsd-host', default='127.0.0.1:8125', type=str, help="StatsD host")
    parser.add_argument('--statsd-flavor', required=False, choices=['dogstatsd', 'influxdb', 'librato', 'signalfx'], help="Select the StatsD flavor")
    parser.add_argument('--launch-terminals', required=False, action='store_true', help="Launch terminals")
    parser.add_argument('--stdio-normal-port', default=54320, type=int, help="Port to send TCP logs from normal world")
    parser.add_argument('--stdio-secure-port', default=54321, type=int, help="Port to send TCP logs from secure world")
    parser.add_argument('--testcase-decoding-mode', choices=['dsl', 'direct'], default='dsl', help="Select the test case decoding mechanism")
    parser.add_argument('--no-affinity', required=False, action='store_true', help="Disable CPU pinning in AFL")

    parser.add_argument('--afl-dir', default='optee/AFLplusplus/', type=str, help="Path to AFL root dir")
    parser.add_argument('--qemu-dir', default='optee/qemu/build/', type=str, help="Path to QEMU build directory")
    parser.add_argument('--execsrv-dir', default='./execsrv/build', type=str, help="Path to exesrv build directory")
    parser.add_argument('--optee-out-dir', default='./optee/out/bin/', type=str, help="Path to optee out dir with compiled images")
    parser.add_argument('--optee-build-dir', default='./optee/build/', type=str, help="Path to optee build dir with build scripts")
    parser.add_argument('--exit', required=False, action='store_true', help='Exit QEMU after tasks are done')
    parser.add_argument('--noout', required=False, action='store_true', help="Supress output from afl")

    subparsers = parser.add_subparsers(dest='command')

    fuzzer = subparsers.add_parser('fuzzer', help="Runner for fuzzer")

    fuzzer_types = fuzzer.add_mutually_exclusive_group(required=True)
    fuzzer_types.add_argument('--normal', action="store_true", required=False, help="Run testcase and revert vm state")
    fuzzer_types.add_argument('--fast', action="store_true", required=False, help="Run testcase and revert vm state hacky way")
    fuzzer_types.add_argument('--norevert', action="store_true", required=False, help="Run from buildroot and don't revert vm state")
    fuzzer_types.add_argument('--tznorevert', action="store_true", required=False, help="Run from trustzone and don't revert vm state")

    fuzzer.add_argument('--skip-cpu-check', action='store_true', required=False, help="Skip AFL's cpu check")
    fuzzer.add_argument('--tmpfs', type=str, required=False, help="Path to tmpf used to store QEMU state in normal mode")
    fuzzer.add_argument('--timeout', type=float, default=50000, help="AFL timeout")
    fuzzer.add_argument('--input', default='in', help='Input directory for AFL')
    fuzzer.add_argument('--output', default='out', help='Output directory for AFL')

    tcgen = subparsers.add_parser('tcgen', help="Testcase generator")
    tcgen.add_argument('tcdir', type=str, help='Directory to store generated testcases')

    subparsers.add_parser('qemu', help='Just run QEMU')

    tc = subparsers.add_parser('testcase', help='Run testcase')
    tc_source = tc.add_mutually_exclusive_group(required=True)
    tc_source.add_argument('--from-path', type=str, required=False, help="Run testcases from file or directory")
    tc_source.add_argument('--hex', type=str, required=False, help="Run testcase from hex")

    return parser.parse_args()

def make_abs(path: str) -> str:
    if not os.path.isabs(path):
        return os.path.join(DIR, path)
    else:
        return path

def prepare_qemu_args(options: argparse.Namespace) -> str:
    fmt = f"""-nographic \
        -serial tcp:localhost:{options.stdio_normal_port} -serial tcp:localhost:{options.stdio_secure_port} \
        -smp 1 \
        -machine virt,secure=on,mte=off,gic-version=3,virtualization=false \
        -cpu max,sve=off,pauth-impdef=on \
        -d unimp -semihosting-config enable=on,target=native \
        -m 1024 \
        -bios bl1.bin           \
        -initrd rootfs.cpio.gz \
        -kernel Image -no-acpi \
        -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000 -netdev user,id=vmnic -device virtio-net-device,netdev=vmnic """

    if options.qemu_log_file is not None:
        fmt += f"-D {make_abs(options.qemu_log_file)} "

    if options.testcase is not None:
        fmt += f"--testcase {options.testcase} "

    if options.drive is not None:
        fmt += f"-drive file={options.drive} "

    args = options.kernel_args
    fmt += f"-append 'console=ttyAMA0,38400 keep_bootcon root=/dev/vda2 mode={options.testcase_decoding_mode} {args if args is not None else ''} {'exit' if options.exit else ''}'"

    return fmt

def prepare_execsrv_args(options: argparse.Namespace) -> str:
    fmt = ""

    if options.execsrv_log_file is not None:
        fmt += f"-l {make_abs(options.execsrv_log_file)} "

    qemu_bin = os.path.join(make_abs(options.qemu_dir), 'qemu-system-aarch64')
    fmt += f"-p '{qemu_bin}' "

    return fmt

def prepare_afl_args(options: argparse.Namespace) -> str:
    fmt = "-Q external -m none "

    if options.timeout is not None:
        fmt += f"-t {options.timeout} "

    fmt += f"-i {make_abs(options.input)} -o {make_abs(options.output)} "

    return fmt

def prepare_env(options: argparse.Namespace) -> Dict[str, str]:
    env = {}

    if 'fuzzer_debug_log' in options and options.fuzzer_debug_log:
        env['FUZZER_DEBUG_LOG'] = '1'

    if 'tcdir' in options:
        env['FUZZER_TC_SAVE_DIR'] = make_abs(options.tcdir)

    if 'fast' in options and options.fast:
        env['FUZZER_FAST_VMSAVE'] = '1'

    if 'afl_debug_log' in options and options.afl_debug_log:
        env['AFL_DEBUG'] = '1'

    if 'skip_cpu_check' in options and options.skip_cpu_check:
        env['AFL_SKIP_CPUFREQ'] = '1'

    if 'enable_statsd' in options and options.enable_statsd:
        env['AFL_STATSD'] = '1'

        if 'statsd_host' in options:
            host, port = options.statsd_host.split(':')
            env['AFL_STATSD_HOST'] = host
            env['AFL_STATSD_PORT'] = port

        if 'statsd_flavor' in options and options.statsd_flavor is not None:
            env['AFL_STATSD_TAGS_FLAVOR'] = options.statsd_flavor
    if 'no_affinity' in options and options.no_affinity:
        env['AFL_NO_AFFINITY'] = '1'

    return env

def is_port_open(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    conn = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return conn == 0

def launch_terminal(port: int, label: str, options: argparse.Namespace):
    optee_build = options.optee_build_dir
    soc_term = os.path.join(optee_build, 'soc_term.py')
    Popen(shlex.split(f"gnome-terminal -t '{label}' -- {soc_term} {port}"))

def launch_terminals(options: argparse.Namespace):
    if 'launch_terminals' in options and options.launch_terminals:
        for port, label in zip([54320, 54321], ["Normal world", "Secure world"]):
            if not is_port_open(port):
                launch_terminal(port, label, options)
                while not is_port_open(port):
                    time.sleep(0.01)

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)

def mount(source, target, fs, options=''):
  ret = libc.mount(None, target.encode(), fs.encode(), 0, options.encode())
  if ret < 0:
    errno = ctypes.get_errno()
    raise OSError(errno, f"Error mounting {source} ({fs}) on {target} with options '{options}': {os.strerror(errno)}")


def run_qemu(options: argparse.Namespace, kernel_args: str | None):
    launch_terminals(options)

    qemu_bin = os.path.join(options.qemu_dir, 'qemu-system-aarch64')
    optee_out_dir = options.optee_out_dir

    options.testcase = None
    options.drive = None
    options.kernel_args = kernel_args

    args = prepare_qemu_args(options)
    env = prepare_env(options)
    Popen([make_abs(qemu_bin)] + shlex.split(args), cwd=optee_out_dir, env=env).communicate()

def run_testcase(options: argparse.Namespace):
    if options.hex is not None:
        run_qemu(options, f"testcase={options.hex}")
    else:
        path = options.from_path

        if os.path.isfile(path):
            with open(path, "rb") as file:
                run_qemu(options, f"testcase={binascii.b2a_hex(file.read()).decode()}")
        else:
            args = ""
            for name in os.listdir(path):
                with open(os.path.join(path, name), "rb") as file:
                    args += f"testcase={binascii.b2a_hex(file.read()).decode()} "
            run_qemu(options, args)

def run_tcgen(options: argparse.Namespace):
    if not os.path.isdir(options.tcdir):
        os.mkdir(options.tcdir)

    run_qemu(options, 'tcgen')

def create_disk_in_tmpfs(options: argparse.Namespace) -> str:
    id = uuid.uuid4()
    drive = os.path.join(make_abs(options.tmpfs), f'{id}.qcow2')
    if not os.path.isfile(drive):
        check_call(shlex.split(f"qemu-img create -f qcow2 {drive} 128M"))
    return drive

def run_fuzzer(options: argparse.Namespace):
    optee_out_dir = make_abs(options.optee_out_dir)

    afl_bin = os.path.join(optee_out_dir, 'afl-fuzz')
    if not os.path.islink(afl_bin):
        src = os.path.join(make_abs(options.afl_dir), 'afl-fuzz')
        os.symlink(src, afl_bin)

    srv_bin = os.path.join(make_abs(options.execsrv_dir), 'srv')

    if not os.path.isdir(options.output):
        os.mkdir(options.output)

    options.testcase = '@@'
    options.drive = None

    if options.normal:
        options.drive = create_disk_in_tmpfs(options)
        options.kernel_args = 'fuzz'
    elif options.fast:
        options.kernel_args = 'fuzz'
    elif options.norevert:
        options.kernel_args = 'host_fuzz'
    else: # tznorevert
        options.kernel_args = 'fuzz_no_reverts'


    qemu_args = prepare_qemu_args(options)
    execsrv_args = prepare_execsrv_args(options)
    afl_args = prepare_afl_args(options)
    env = prepare_env(options)

    cmd = f"{afl_bin} {afl_args} -- {srv_bin} {execsrv_args} -- {qemu_args}"
    print(cmd)
    print(env)
    launch_terminals(options)



    if options.afl_log_file:
        out = open(options.afl_log_file, "wb")
        err = open(options.afl_log_file + ".err", "wb")
        return Popen(shlex.split(cmd), cwd=optee_out_dir, env=env, stdout=out, stderr=err)
    elif options.noout:
        return Popen(shlex.split(cmd), cwd=optee_out_dir, env=env, stdout=PIPE, stderr=PIPE)
    else:
        return Popen(shlex.split(cmd), cwd=optee_out_dir, env=env)



def main():
    args = parse_args()
    print(args)

    if args.command == 'qemu':
        run_qemu(args, None)
    elif args.command == 'testcase':
        run_testcase(args)
    elif args.command == 'tcgen':
        run_tcgen(args)
    elif args.command == 'fuzzer':
        run_fuzzer(args)().communicate()

    if args.drive is not None:
        os.remove(args.drive)

if __name__ == '__main__':
    main()

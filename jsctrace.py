#!/usr/bin/python
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2012-2016 Brendan Gregg, Sasha Goldshtein.
# Copyright (C) 2020 Igalia S.L.

import argparse
from time import sleep
import enum
import signal
import sys
from bcc import USDT, BPF

DEBUG = False

class Probe():
    "Parse, load and attach BPF probes"
    def __init__(self, probe_spec, kernel_stack, user_stack, use_regex=False,
                 pid=None, per_pid=False, cpu=None):
        self.kernel_stack = kernel_stack
        self.user_stack = user_stack

        if DEBUG:
            print(probe_spec)

        self._parse_spec(probe_spec)

        if (self.type == "p" and self.library) or self.type == "u":
            libpath = BPF.find_library(self.library)
            if libpath is None:
                # This might be an executable (e.g. 'bash')
                libpath = BPF.find_exe(self.library)
            if libpath is None or len(libpath) == 0:
                raise Exception("unable to find library %s" % self.library)
            self.library = str(libpath, 'ascii')

        self.pid = pid
        # FIXME: don't hardcode this here.
        self.per_pid = True
        self.cpu = cpu
        self.matched = 0
        self.bpf = None
        self.usdt = None

    def _parse_spec(self, spec):
        parts = spec.split(":")
        # Two special cases: 'func' means 'p::func', 'lib:func' means
        # 'p:lib:func'. Other combinations need to provide an empty
        # value between delimiters, e.g. 'r::func' for a kretprobe on
        # the function func.
        if len(parts) == 1:
            parts = ["p", "", parts[0]]
        elif len(parts) == 2:
            parts = ["p", parts[0], parts[1]]

        if len(parts[0]) == 0:
            self.type = "p"
        elif parts[0] in ["p", "r", "t", "u"]:
            self.type = parts[0]
        else:
            raise Exception("probe type must be '', 'p', 't', 'r', " +
                            "or 'u', but got '%s'" % parts[0])

        if self.type == "u":
            # u:<library>[:<provider>]:<probe> where :<provider> is optional
            self.library = parts[1]
            self.pattern = ":".join(parts[2:])
        else:
            self.library = ':'.join(parts[1:-1])
            self.pattern = parts[-1]

    def load(self):
        ctx_name = "ctx"
        stack_trace = ""
        if self.user_stack:
            stack_trace += """
            key.user_stack_id = stack_traces.get_stackid(
            %s, BPF_F_USER_STACK
            );""" % (ctx_name)
        else:
            stack_trace += "key.user_stack_id = -1;"
        if self.kernel_stack:
            stack_trace += """
            key.kernel_stack_id = stack_traces.get_stackid(
            %s, 0
            );""" % (ctx_name)
        else:
            stack_trace += "key.kernel_stack_id = -1;"

        trace_count_text = """
int trace_count(void *ctx) {
    FILTER
    struct key_t key = {};
    key.tgid = GET_TGID;
    STORE_COMM
    %s
    counts.increment(key);
    return 0;
}
        """
        trace_count_text = trace_count_text % (stack_trace)

        bpf_text = """#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    // no pid (thread ID) so that we do not needlessly split this key
    u32 tgid;
    int kernel_stack_id;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE(stack_traces, 1024);
        """

        filter_text = []
        trace_count_text = trace_count_text.replace('FILTER', '\n    '.join(filter_text))

        # Do per-pid statistics iff -P is provided
        if self.per_pid:
            trace_count_text = trace_count_text.replace(
                'GET_TGID',
                'bpf_get_current_pid_tgid() >> 32')
            trace_count_text = trace_count_text.replace(
                'STORE_COMM',
                'bpf_get_current_comm(&key.name, sizeof(key.name));')
        else:
            # skip splitting on PID so these aggregate
            # together, and don't store the process name.
            trace_count_text = trace_count_text.replace('GET_TGID', '0xffffffff')
            trace_count_text = trace_count_text.replace('STORE_COMM', '')

        if self.type == "u":
            self.usdt = USDT(path=self.library, pid=self.pid)
            for probe in self.usdt.enumerate_probes():
                if not self.pid and (str(probe.bin_path, 'ascii') != self.library):
                    continue
                parts = self.pattern.split(":")
                if len(parts) == 1:
                    provider_name = None
                    usdt_name = parts[0].encode("ascii")
                else:
                    provider_name = parts[0]
                    usdt_name = parts[1]
                if (str(probe.name, 'ascii') == usdt_name and
                        str(probe.provider, 'ascii') == provider_name):
                    # This hack is required because the bpf_usdt_readarg
                    # functions generated need different function names for
                    # each attached probe. If we just stick to trace_count,
                    # we'd get multiple bpf_usdt_readarg helpers with the same
                    # name when enabling more than one USDT probe.
                    new_func = "trace_count_%d" % self.matched
                    bpf_text += trace_count_text.replace("trace_count", new_func)
                    self.usdt.enable_probe(str(probe.name, 'ascii'), new_func)
                    self.matched += 1
            if DEBUG:
                print(self.usdt.get_text())
        else:
            bpf_text += trace_count_text

        if DEBUG:
            print(bpf_text)
        self.bpf = BPF(text=bpf_text,
                       usdt_contexts=[self.usdt] if self.usdt else [])

    def attach(self):
        if self.type == "p":
            if self.library:
                self.bpf.attach_uprobe(name=self.library,
                                       sym_re=self.pattern,
                                       fn_name="trace_count",
                                       pid=self.pid or -1)
                self.matched = self.bpf.num_open_uprobes()
            else:
                self.bpf.attach_kprobe(event_re=self.pattern,
                                       fn_name="trace_count")
                self.matched = self.bpf.num_open_kprobes()
        elif self.type == "t":
            self.bpf.attach_tracepoint(tp_re=self.pattern,
                                       fn_name="trace_count")
            self.matched = self.bpf.num_open_tracepoints()
        elif self.type == "u":
            pass    # Nothing to do -- attach already happened in `load`

        if self.matched == 0:
            raise Exception("No functions matched by pattern %s" %
                            self.pattern)

class ToolEnum(enum.IntEnum):
    LOCK = 1

    def __str__(self):
        return self.name.lower()

    def __repr__(self):
        return str(self)

    @staticmethod
    def argparse(s):
        try:
            return ToolEnum[s.upper()]
        except KeyError:
            return s

class Tool():
    "Parse arguments and run the probe loop"
    JSC_LOCK_TRACE_ID = "jsc:wtflock"
    examples = """
jsctrace lock -b <path to JSC binary>
"""

    def __init__(self):
        parser = argparse.ArgumentParser(
            description="Trace the performance of different JavaScriptCore subsystems",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=Tool.examples)
        parser.add_argument("tool", type=ToolEnum.argparse,
                            choices=list(ToolEnum),
                            help="the type of tool to run on JavaScriptCore")
        parser.add_argument("-b", "--binary",
                            required=True, type=str, dest="binary",
                            help="the JSC binary to use for tracing")
        parser.add_argument("-v", "--verbose",
                            action="store_true",
                            help="Print resulting BPF program code before executing")
        parser.add_argument("-U", "--user-stack",
                            action="store_true", dest="user_stack",
                            help="output user stack trace", default=True)
        parser.add_argument("-K", "--kernel-stack",
                            action="store_true", dest="kernel_stack",
                            help="output kernel stack trace", default=False)
        parser.add_argument("-i", "--interval", help="summary interval, seconds")
        parser.add_argument("-D", "--duration", help="total duration of trace, seconds")
        parser.add_argument("-f", "--folded", action="store_true", help="output folded format")
        parser.add_argument("-s", "--offset", action="store_true", help="show address offsets")
        parser.add_argument("-p", "--pid", type=int, help="trace this PID only")

        self.args = parser.parse_args()

        if self.args.duration and not self.args.interval:
            self.args.interval = self.args.duration
        if not self.args.interval:
            self.args.interval = 99999999

        self.need_delimiter = False
        self.builtin_probe_spec = "u:" + self.args.binary + ":" + Tool.JSC_LOCK_TRACE_ID
        self.probe = Probe(self.builtin_probe_spec,
                           self.args.kernel_stack, self.args.user_stack)

    def _print_uframe(self, addr, pid):
        print("  ", end="")
        if self.args.verbose:
            print("%-16x " % addr, end="")
        if self.args.offset:
            print("%s" % self.probe.bpf.sym(addr, pid, show_offset=True))
        else:
            print("%s" % self.probe.bpf.sym(addr, pid))

    def _print_kframe(self, addr):
        print("  ", end="")
        if self.args.verbose:
            print("%-16x " % addr, end="")
        if self.args.offset:
            print("%s" % self.probe.bpf.ksym(addr, show_offset=True))
        else:
            print("%s" % self.probe.bpf.ksym(addr))

    def _print_comm(self, comm, pid):
        print("    %s [%d]" % (comm, pid))

    @staticmethod
    def _signal_ignore(_signal, _frame):
        print()

    def run(self):
        self.probe.load()
        self.probe.attach()

        if not self.args.folded:
            print("Tracing %d functions... Hit Ctrl-C to end." %
                  (self.probe.matched))
        b = self.probe.bpf
        exiting = 0 if self.args.interval else 1
        seconds = 0
        while True:
            try:
                sleep(int(self.args.interval))
                seconds += int(self.args.interval)
            except KeyboardInterrupt:
                exiting = 1
                # as cleanup can take many seconds, trap Ctrl-C:
                signal.signal(signal.SIGINT, Tool._signal_ignore)

            if self.args.duration and seconds >= int(self.args.duration):
                exiting = 1

            counts = self.probe.bpf["counts"]
            stack_traces = self.probe.bpf["stack_traces"]
            for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
                user_stack = [] if k.user_stack_id < 0 else \
                    stack_traces.walk(k.user_stack_id)
                kernel_stack = [] if k.kernel_stack_id < 0 else \
                    stack_traces.walk(k.kernel_stack_id)

                if self.args.folded:
                    # print folded stack output
                    user_stack = list(user_stack)
                    kernel_stack = list(kernel_stack)
                    line = [k.name.decode('utf-8', 'replace')] + \
                        [b.sym(addr, k.tgid).decode('utf-8', 'replace') for addr in
                         reversed(user_stack)] + \
                         (self.need_delimiter and ["-"] or []) + \
                         [b.ksym(addr).decode('utf-8', 'replace') for addr in reversed(kernel_stack)]
                    print("%s %d" % (";".join(line), v.value))
                else:
                    # print multi-line stack output
                    for addr in kernel_stack:
                        self._print_kframe(addr)
                    if self.need_delimiter:
                        print("    --")
                    for addr in user_stack:
                        self._print_uframe(addr, k.tgid)
                    if not self.args.pid and k.tgid != 0xffffffff:
                        self._print_comm(k.name, k.tgid)
                    print("    %d\n" % v.value)
            counts.clear()

            if exiting:
                if not self.args.folded:
                    print("Detaching...")
                sys.exit()

if __name__ == "__main__":
    try:
        Tool().run()
    except Exception:
        if sys.exc_info()[0] is not SystemExit:
            print(sys.exc_info()[1])

Right now the tool supports printing the top stack traces that hit a
USDT for WTF::Lock in WebKit (see:
https://github.com/xanlpz/webkit/commit/c5031df7b646706e5e075a8bd5775aecf08c80b2).

Once you have the patch applied to your WebKit tree, the application
can be run as:

> sudo jsctrace.py lock -b <path to JSC binary>

Then you can launch a JSC process and the tool will gather the
statistics. After closing the app you'll be presented with a bottom to
top list of the hottest lock traces.

At this point, because of a BCC limitation, the tracing
process (jsctrace.py) needs to be closed *before* the JSC process
exits, otherwise the symbols for the stack trace won't be
resolved. See: https://github.com/iovisor/bcc/issues/2883


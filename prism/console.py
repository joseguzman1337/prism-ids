from typing import Optional, Any, TYPE_CHECKING
from sys import stdout
from signal import signal, SIGPIPE, SIG_IGN
import logging

# mypy has issues with classes that are generic in stubs,
# but not at runtime. This is apparently the solution
if TYPE_CHECKING:
    # this is only processed by mypy
    StreamHandler = logging.StreamHandler[Any]
else:
    # this is not seen by mypy but will be executed at runtime
    StreamHandler = logging.StreamHandler

# Just importing this code allows us to use logging for stdout without printing
# backtraces just because we got SIGPIPE from writing to stdout when the script
# is being used with a pager like 'less' in some shell pipeline. In other
# words, work like a regular command-line utility


class DualFormatter(logging.Formatter):
    _info_fmt = logging.Formatter('%(message)s')
    _err_fmt = logging.Formatter('%(levelname)s: %(message)s')
    _dbg_fmt = logging.Formatter('%(module)s:%(lineno)d: %(message)s')

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno >= logging.WARNING:
            return self._err_fmt.format(record)
        elif record.levelno <= logging.DEBUG:
            return self._dbg_fmt.format(record)
        else:
            return self._info_fmt.format(record)


_fmt = DualFormatter()


class Handler(StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except RecursionError:
            raise
        except BrokenPipeError:
            raise SystemExit(1)
        except Exception:
            self.handleError(record)


_stdio_handler = Handler(stream=stdout)
_stdio_handler.setFormatter(_fmt)


def sigpipe_ignore() -> None:
    signal(SIGPIPE, SIG_IGN)


def log_module_init(name: Optional[str],
                    level: int = logging.INFO,
                    ) -> logging.Logger:
    log = logging.getLogger(name)
    log.addHandler(_stdio_handler)
    log.setLevel(level)
    return log


sigpipe_ignore()
log_module_init(None).name = 'prism'

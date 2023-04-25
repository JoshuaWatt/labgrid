import re

import logging

import attr

from .step import steps, StepEvent


def basicConfig(**kwargs):
    logging.basicConfig(**kwargs)
    root = logging.getLogger()

    root.handlers[0].setFormatter(StepFormatter())


logging.CONSOLE = logging.INFO - 1
logging.addLevelName(logging.CONSOLE, "CONSOLE")

# Use composition instead of inheritance
class StepFormatter:
    def __init__(
        self, *args, indent=True, color=None, long_result=False, parent=None, **kwargs
    ):
        if parent:
            self.formatter = parent
        else:
            self.formatter = logging.Formatter(*args, **kwargs)
        self.long_result = long_result
        self.indent = indent
        self.indent_level = 0
        self.bufs = dict()
        self.re_vt100 = re.compile(r"(\x1b\[|\x9b)[^@-_a-z]*[@-_a-z]|\x1b[@-_a-z]")
        self.color = color

    def format(self, record):
        old_msg = record.msg
        try:
            if self.indent:
                if hasattr(record, "indent_level"):
                    self.indent_level = record.indent_level

                record.msg = (" " * self.indent_level) + record.msg

                self.indent_level = getattr(
                    record, "next_indent_level", self.indent_level
                )

            return self.formatter.format(record)
        finally:
            record.msg = old_msg


@attr.s
class SerialLoggingReporter:
    bufs = attr.ib(
        default=attr.Factory(dict), validator=attr.validators.instance_of(dict)
    )
    loggers = attr.ib(
        default=attr.Factory(dict), validator=attr.validators.instance_of(dict)
    )
    lastevent = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(StepEvent)),
    )
    re_vt100 = attr.ib(
        default=re.compile(r"(\x1b\[|\x9b)[^@-_a-z]*[@-_a-z]|\x1b[@-_a-z]")
    )

    def __attrs_post_init__(self):
        steps.subscribe(self.notify)

    def vt100_replace_cr_nl(self, buf):
        string = self.re_vt100.sub("", buf.decode("utf-8", errors="replace"))
        string = string.replace("\r", "␍")
        string = string.replace("\n", "␤")
        string = string.replace("\b", "␈")
        string = string.replace("\a", "␇")
        string = string.replace("\v", "␋")
        string = string.replace("\f", "␌")
        return string

    def __create_message(self, event, data):
        return "{source} {dirind} {data}␍␤".format(
            source=event.step.source,
            dirind="<" if event.step.get_title() == "read" else ">",
            data=data,
        )

    def notify(self, event):
        step = event.step
        state = event.data.get("state")
        if step.tag == "console":
            self.loggers[step.source] = logging.getLogger(
                f"SerialLogger.{step.source.__class__.__name__}.{step.source.target}"
            )
            logger = self.loggers[step.source]

            if state == "stop" and step.get_title() == "read" and step.result:
                if step.source not in self.bufs.keys():
                    self.bufs[step.source] = b""
                self.bufs[step.source] += step.result
                *parts, self.bufs[step.source] = self.bufs[step.source].split(b"\r\n")

                self.lastevent = event

                for part in parts:
                    data = self.vt100_replace_cr_nl(part)
                    logger.log(logging.CONSOLE, self.__create_message(event, data))

            elif state == "start" and step.args and "data" in step.args:
                data = self.vt100_replace_cr_nl(step.args["data"])
                logger.log(logging.CONSOLE, self.__create_message(event, data))

    def flush(self):
        if self.lastevent is None:
            return

        for source, logger in self.loggers.items():
            data = self.vt100_replace_cr_nl(self.bufs[source])
            if data:
                logger.log(logging.CONSOLE, self.__create_message(self.lastevent, data))
            self.bufs[source] = b""


class StepLogger:
    _started = False
    _logger = None
    _serial_logger = None
    _long_result = False

    def __attrs_post_init__(self):
        from warnings import warn

        warn(
            "StepLogger should not be instantiated, use StepReporter.start()/.stop() instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    @classmethod
    def start(cls, long_result=False):
        """starts the StepLogger"""
        assert not cls._started
        if cls._logger is None:
            cls._logger = logging.getLogger("StepLogger")
        steps.subscribe(cls.notify)
        cls._serial_logger = SerialLoggingReporter()
        cls._started = True
        cls._long_result = long_result

    @classmethod
    def stop(cls):
        """stops the StepLogger"""
        assert cls._started
        steps.unsubscribe(cls.notify)
        cls._started = False

    @classmethod
    def get_prefix(cls, event):
        if event.step.exception:
            return "⚠"
        elif event.data.get("state") == "start":
            return "→"
        elif event.data.get("state") == "stop":
            return "←"
        elif event.data.get("skip", None):
            return "↓"
        else:
            return ""

    @staticmethod
    def format_arguments(args):
        if args is None:
            return ""
        if isinstance(args, dict):
            collected_args = []
            for k, v in args.items():
                collected_args.append("{}={}".format(k, v))

            return " ".join(collected_args)
        else:
            return "{}".format(args)

    @staticmethod
    def format_duration(duration):
        if duration < 0.001:
            return ""

        return "[{:.3f}s]".format(duration)

    @classmethod
    def format_result(cls, result):
        if result is None:
            return ""

        if cls._long_result:
            return "result={} ".format(result)

        if len(str(result)) < 60:
            return "result={} ".format(result)
        else:
            return "result={:.59}… ".format(repr(result))

    @classmethod
    def __get_message(cls, event):
        m = "{prefix} {source} {title} {args} {result}{duration}".format(
            prefix=cls.get_prefix(event),
            source=event.step.__class__.__name__,
            title=event.step.title,
            args=cls.format_arguments(event.data.get("args", {})),
            result=cls.format_result(event.data.get("result", None)),
            duration=cls.format_duration(event.data.get("duration", 0.0)),
        )

        if event.step.exception:
            m += f" exception={event.step.exception}"

        reason = event.data.get("skip", None)
        if reason:
            m += f"skipped={reason}"

        return m

    @classmethod
    def get_next_indent(cls, event):
        if event.step.exception:
            return event.step.level

        if event.data.get("state") == "start":
            return event.step.level + 1

        return event.step.level

    @classmethod
    def notify(cls, event):
        if event.step.tag == "console":
            return
        if cls._serial_logger:
            cls._serial_logger.flush()

        message = cls.__get_message(event)

        level = logging.INFO
        extra = {
            "indent_level": event.step.level,
            "next_indent_level": cls.get_next_indent(event),
        }
        cls._logger.log(level, message, extra=extra)

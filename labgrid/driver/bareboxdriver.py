# pylint: disable=no-member
import logging
import re
import shlex

import attr
from pexpect import TIMEOUT

from ..exceptions import CommandProcessBusy
from ..factory import target_factory
from ..protocol import CommandProtocol, ConsoleProtocol, LinuxBootProtocol
from ..step import step
from ..util import gen_marker, Timeout, ConsoleMarkerProcess
from .common import Driver
from .commandmixin import CommandMixin


@target_factory.reg_driver
@attr.s(eq=False)
class BareboxDriver(CommandMixin, Driver, CommandProtocol, LinuxBootProtocol):
    """BareboxDriver - Driver to control barebox via the console.
       BareboxDriver binds on top of a ConsoleProtocol.

       On activation, the BareboxDriver will look for the barebox prompt on the
       console, stopping any autoboot counters if necessary, and provide access
       to the barebox shell.

    Args:
        prompt (str): barebox prompt to match
        autoboot (regex): optional, autoboot message to match
        interrupt (str): optional, string to interrupt autoboot (use "\x03" for CTRL-C)
        bootstring (regex): optional, regex indicating that the Linux Kernel is booting
        password (str): optional, password to use for access to the shell
        login_timeout (int): optional, timeout for access to the shell
    """
    bindings = {"console": ConsoleProtocol, }
    prompt = attr.ib(default="", validator=attr.validators.instance_of(str))
    autoboot = attr.ib(default="stop autoboot", validator=attr.validators.instance_of(str))
    interrupt = attr.ib(default="\n", validator=attr.validators.instance_of(str))
    bootstring = attr.ib(default=r"Linux version \d", validator=attr.validators.instance_of(str))
    password = attr.ib(default="", validator=attr.validators.instance_of(str))
    login_timeout = attr.ib(default=60, validator=attr.validators.instance_of(int))

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        self.re_vt100 = re.compile(
            r'(\x1b\[|\x9b)[^@-_a-z]*[@-_a-z]|\x1b[@-_a-z]'
        )
        self.logger = logging.getLogger(f"{self}:{self.target}")
        self._status = 0
        self._process = None

    def on_activate(self):
        """Activate the BareboxDriver

        This function tries to login if not already active
        """
        if self._status == 0:
            self._await_prompt()

    def on_deactivate(self):
        """Deactivate the BareboxDriver

        Simply sets the internal status to 0
        """
        self._status = 0

    def _popen(self, cmd: str):
        if self._process is not None:
            raise CommandProcessBusy()

        # FIXME: use codec, decodeerrors
        marker = gen_marker()
        # hide marker from expect
        hidden_marker = f'"{marker[:4]}""{marker[4:]}"'
        cmp_command = f'''echo -o /cmd {shlex.quote(cmd)}; echo {hidden_marker}; sh /cmd; echo {hidden_marker} $?;'''  # pylint: disable=line-too-long

        self.console.sendline(cmp_command)
        self.console.expect(marker)

        self._process = ConsoleMarkerProcess(
            self.console,
            marker,
            self.prompt,
            on_exit=self._handle_process_exit
        )
        return self._process

    def _handle_process_exit(self, process):
        if self._process is process:
            self._process = None

    @Driver.check_active
    @step(args=['cmd'])
    def run(self, cmd: str, *, timeout: int = 30):  # pylint: disable=unused-argument
        return self._run(cmd, timeout=timeout)

    def _run(self, cmd: str, *, timeout: int = 30, codec: str = "utf-8", decodeerrors: str = "strict"):  # pylint: disable=unused-argument,line-too-long
        """
        Runs the specified command on the shell and returns the output.

        Args:
            cmd (str): command to run on the shell
            timeout (int): optional, timeout in seconds

        Returns:
            Tuple[List[str],List[str], int]: if successful, None otherwise
        """
        if self._status == 1:
            with self._popen(cmd) as p:
                output = p.read_to_end(timeout=timeout)
                # Remove VT100 Codes and split by newline
                data = self.re_vt100.sub('', output.decode('utf-8')).split('\r\n')[1:-1]
                self.logger.debug("Received Data: %s", data)
                return (data, [], p.exitcode)

        return None

    @Driver.check_active
    @step(args=['cmd'], result=True)
    def popen(self, cmd: str):
        return self._popen(cmd)

    @Driver.check_active
    @step()
    def reset(self):
        """Reset the board via a CPU reset
        """
        self._status = 0
        self.console.sendline("reset")
        self._await_prompt()

    def get_status(self):
        """Retrieve status of the BareboxDriver
        0 means inactive, 1 means active.

        Returns:
            int: status of the driver
        """
        return self._status

    def _check_prompt(self):
        """
        Internal function to check if we have a valid prompt.
        It sets the internal _status to 1 or 0 based on the prompt detection.
        """
        marker = gen_marker()
        # hide marker from expect
        hidden_marker = f'"{marker[:4]}""{marker[4:]}"'
        self.console.sendline(f"echo {hidden_marker}")
        try:
            self.console.expect(f"{marker}", timeout=2)
            self.console.expect(self.prompt, timeout=1)
            self._status = 1
        except TIMEOUT:
            self._status = 0
            raise

    @step()
    def _await_prompt(self):
        """Awaits the prompt and enters the shell"""

        timeout = Timeout(float(self.login_timeout))

        # We call console.expect with a short timeout here to detect if the
        # console is idle, which would result in a timeout without any changes
        # to the before property. So we store the last before value we've seen.
        # Because pexpect keeps any read data in it's buffer when a timeout
        # occours, we can't lose any data this way.
        last_before = None
        password_entered = False

        expectations = [self.prompt, self.autoboot, "Password: ", TIMEOUT]
        while True:
            index, before, _, _ = self.console.expect(
                expectations,
                timeout=2
            )

            if index == 0:
                # we got a prompt. no need for any further action to activate
                # this driver.
                self._status = 1
                break

            elif index == 1:
                # we need to interrupt autoboot
                self.console.write(self.interrupt.encode('ASCII'))

            elif index == 2:
                # we need to enter the password
                if not self.password:
                    raise Exception("Password entry needed but no password set")
                if password_entered:
                    # we already sent the password, but got the pw prompt again
                    raise Exception("Password was not correct")
                self.console.sendline(self.password)
                password_entered = True

            elif index == 3:
                # expect hit a timeout while waiting for a match
                if before == last_before:
                    # we did not receive anything during the previous expect cycle
                    # let's assume the target is idle and we can safely issue a
                    # newline to check the state
                    self.console.sendline("")

                if timeout.expired:
                    raise TIMEOUT(
                        f"Timeout of {self.login_timeout} seconds exceeded during waiting for login"  # pylint: disable=line-too-long
                    )

            last_before = before

        self._check_prompt()

    @Driver.check_active
    def await_boot(self):
        """Wait for the initial Linux version string to verify we succesfully
        jumped into the kernel.
        """
        self.console.expect(self.bootstring)

    @Driver.check_active
    def boot(self, name: str):
        """Boot the default or a specific boot entry

        Args:
            name (str): name of the entry to boot"""
        if name:
            self.console.sendline(f"boot -v {name}")
        else:
            self.console.sendline("boot -v")

from enum import Enum

from regex import P
from patchwork import Patchwork
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import time
import os
import subprocess
import logging
import random
import string
import shutil
import argparse
import configparser
import threading
import typing
import smtplib
import traceback

class EndTest(Exception):
    """
    End of Test
    """

class Verdict(Enum):
    PENDING = 0
    PASS = 1
    FAIL = 2
    ERROR = 3
    SKIP = 4
    WARNING = 5

def patchwork_state(verdict: Verdict):
    """
    Convert verdict to patchwork state
    """
    if verdict == Verdict.PASS:
        return 1
    if verdict == Verdict.WARNING:
        return 2
    if verdict == Verdict.FAIL:
        return 3

    return 0

def parse_args():
    parser = argparse.ArgumentParser(
        description="Check patch style in the pull request")
    parser.add_argument('-c', '--config-file', default='config.ini',
                        help='Configuration file or URL')
    parser.add_argument('-l', '--show-test-list', action='store_true',
                        help='Display supported CI tests')
    parser.add_argument('-p', '--pr-num', required=False, type=int,
                        help='Pull request number')
    parser.add_argument('-r', '--repo', required=False,
                        help='Github repo in :owner/:repo')
    parser.add_argument('-s', '--src_path', required=True,
                        help="Path to the project source")
    parser.add_argument('-e', '--ell-path', default='ell',
                        help='Path to ELL source')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')
    parser.add_argument('-x', '--external-trigger',  action='store_true',
                        help='Triggered from external repository')

    return parser.parse_args()

def init_logging(verbose: bool):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s:%(levelname)-8s:%(message)s\r')
    ch.setFormatter(formatter)

    logger.addHandler(ch)

    logger.info("Logger is initialized: level=%s",
                 logging.getLevelName(logger.getEffectiveLevel()))

    return logger

def init_config(file: str, logger: logging.Logger):
    config = configparser.ConfigParser()

    logger.info("Loading config file: %s" % file)
    config.read(file)

    for section in config.sections():
        logger.debug("[%s]" % section)
        for (key, val) in config.items(section):
            logger.debug("   %s : %s" % (key, val))

    return config

def path_resolve(path: str):
    if not os.path.isabs(path):
        if not os.environ.get('GITHUB_WORKSPACE', None):
            raise Exception('GITHUB_WORKSPACE must be set to use relative paths')

        path = os.path.join(os.environ['GITHUB_WORKSPACE'], path)

    return path

def config_enable(config: dict, name: str):
    """
    Check "enable" in config[name].
    Return False if it is specifed otherwise True
    """

    if name in config:
        if 'enable' in config[name]:
            if config[name]['enable'] == 'no':
                return False

    return True

def config_submit_pw(config: dict, name: str):
    """
    Check "submit_pw" in config[name]
    Return True if it is specified and value is "yes"
    """

    if not config_enable(config, name):
        return False

    if name in config:
        if 'submit_pw' in config[name]:
            if config[name]['submit_pw'] == 'yes':
                return True

    return False

def run_thread(suite: dict, constructor):
    src = suite[constructor.inherit_src].src_dir if constructor.inherit_src else None

    test = constructor(src_dir=src)
    suite[constructor.name] = test


    for dep in test.depends:
        if dep == '*':
            continue

        if suite[dep].verdict == Verdict.PASS:
            continue

        test.linfo("%s did not pass. skipping %s test" % (dep, test.name))
        test.submit_result(Verdict.SKIP, "%s SKIP" % test.name)
        test.verdict = Verdict.SKIP
        test.output = "%s was skipped" % test.name
        return

    try:
        test.linfo("%s Started" % test.name)
        test.start_timer()
        test.run()
    except EndTest:
        if test.verdict == Verdict.SKIP:
            test.linfo("%s Skipped" % test.name)
    except Exception:
        print("%s failed with uncaught exception:" % test.name)
        traceback.print_exc()
        test.verdict = Verdict.FAIL
    finally:
        test.end_timer()

        test.linfo("%s Ended" % test.name)

class Pipeline:
    def __init__(self, entries: dict, runner: typing.Callable):
        l = list(entries.values())
        self.runner = runner
        self.entries = entries
        self.pool = []
        isolated = False

        # Loop until all tests have finished
        while len(l) != 0:
            done = []

            for test in l:
                # Start tests with met dependencies that aren't already running
                if self.has_deps(test) or self.is_running(test):
                    continue

                # If this test should be isolated don't start until the current
                # pools is empty. Or if an isolated test is already running
                # don't start any others.
                if (test.isolate and len(self.pool) > 0) or isolated:
                    continue

                isolated = test.isolate

                p = threading.Thread(target=self.runner,
                                        args=(self.entries, test), daemon=False)
                p.start()
                self.pool.append((p, test))

            # Check if any have finished
            for p, test in self.pool:
                p.join(1)
                if p.is_alive():
                    continue

                if isolated:
                    isolated = False

                done.append((p, test))
                l.remove(test)

            # Remove threads that are done
            self.pool = list(set(self.pool) - set(done))

    def has_deps(self, test):
        # No dependencies
        if not test.depends:
            return False

        # Depends on all other tests
        if '*' in test.depends:
            for t in self.entries.values():
                # Ignore others with '*' depends
                if '*' in t.depends:
                    continue

                if t.verdict == Verdict.PENDING:
                    return True

            return False

        # Are all dependencies satisfied?
        for d in test.depends:
            if self.entries[d].verdict == Verdict.PENDING:
                return True

        return False

    def is_running(self, test):
        for _, t in self.pool:
            if test == t:
                return True

        return False

class CiBase:
    """
    Base class for CI Tests.
    """
    name = None
    display_name = None
    desc = None
    start_time = 0
    end_time = 0
    src_dir = None
    # If true, don't copy any source
    disable_src_dir = False
    # List of other CiBase subclass names which need to run prior
    depends = []
    # Name of another CiBase who's src_dir should be used
    inherit_src = False
    # Use singleton argument, patchwork, logger, and config objects
    args = parse_args()
    patchwork = None
    logger = init_logging(args.verbose)
    # The full configuration
    _config = init_config(args.config_file, logger)
    # Settings for specific instance i.e. _config[self.name]
    settings = None
    # If true, don't run test concurrently with others
    isolate = False
    workdir = os.environ.get('WORKDIR', '/tmp')

    verdict = Verdict.PENDING
    output = ""
    ext_skip_pending = False

    #
    # Support several ways to initialize src_dir:
    #
    # 1. Copy src_path to a random <WORKDIR>/XXXXXXX directory (default)
    # 2. Copy provided src_dir to <WORKDIR>/<basename> of src_dir i.e. keep dir name
    # 3. Inherit src_dir from a dependent test, no copies are done.
    #
    def __init__(self, src_dir=None):
        if self.name in self._config:
            self.settings = self._config[self.name]

        if self.disable_src_dir:
            return

        if self.inherit_src:
            self.src_dir = src_dir
            self.ldebug("%s using inherited src_dir=%s" % (self.name, src_dir))
            return

        copy_from = src_dir if src_dir else self.args.src_path

        if src_dir:
            self.src_dir = os.path.join(self.workdir, os.path.basename(src_dir))
        else:
            self.src_dir = os.path.join(self.workdir, ''.join(random.choices(
                                            string.ascii_uppercase +
                                            string.digits, k = 10)))

        if os.path.exists(self.src_dir):
                shutil.rmtree(self.src_dir)

        shutil.copytree(copy_from, self.src_dir)
        self.ldebug("%s using src_dir=%s" % (self.name, self.src_dir))

    def __del__(self):
        if self.inherit_src or self.disable_src_dir:
            return

        if os.path.exists(self.src_dir):
            shutil.rmtree(self.src_dir)

        self.ldebug("Source contents removed from %s" % self.src_dir)

    # enable/sumbit_pw are structured this way in order to access from both
    # the class constructor and instantiated class:
    #
    #   e.g. CheckPatch.enable
    #        CheckPatch().enable
    @classmethod
    @property
    def enable(cls):
        return config_enable(cls._config, cls.name)

    @classmethod
    @property
    def submit_pw(cls):
        return config_submit_pw(cls._config, cls.name)

    @classmethod
    def run(cls):
        # Populate the test suite
        cls.suite = dict([(t.name, t) for t in cls.__subclasses__() if t.enable])

        if cls.args.show_test_list:
            print("Running tests:")
            for name in cls.suite.keys():
                print(name)

        # Start the thread pipeline
        Pipeline(cls.suite, run_thread)

    @classmethod
    def print_results(cls):
        for t in cls.suite.values():
            print("%18s: \t%s\t%d sec" % (t.name, str(t.verdict), t.elapsed()))

    @classmethod
    def linfo(cls, *args):
        cls.logger.info(*args)

    @classmethod
    def ldebug(cls, *args):
        cls.logger.debug(*args)

    @classmethod
    def lerror(cls, *args):
        cls.logger.error(*args)

    def success(self):
        self.verdict = Verdict.PASS
        raise EndTest

    def error(self, msg: str):
        self.verdict = Verdict.ERROR
        self.output = msg
        raise EndTest

    def skip(self, msg: str):
        self.verdict = Verdict.SKIP
        self.output = msg
        raise EndTest

    def add_failure(self, msg: str):
        self.verdict = Verdict.FAIL
        if not self.output:
            self.output = msg
        else:
            self.output += "\n" + msg

    def add_failure_end_test(self, msg: str):
        self.add_failure(msg)
        raise EndTest

    def start_timer(self):
        self.start_time = time.time()

    def end_timer(self):
        self.end_time = time.time()

    def elapsed(self):
        if self.start_time == 0:
            return 0
        if self.end_time == 0:
            self.end_timer()
        return self.end_time - self.start_time

    @classmethod
    def submit_result(cls, verdict: Verdict, description=None, patch=None):
        """
        Submit the result to Patchwork. Nearly all tests post to the first patch
        in the series so don't require a specific patch being passed in (this
        can be forced with patch=)
        """
        job = os.environ.get('GITHUB_JOB', None)
        if job:
            name = '%s-%s' % (job, cls.name)

        if not cls.submit_pw:
            return

        if not cls.patchwork:
            return

        if not patch:
            patch = cls.patchwork[0]

        if not description:
            description = cls.display_name

        cls.ldebug("Submitting the result to Patchwork")
        pw_output = cls.patchwork.post_result(patch, patchwork_state(verdict),
                                                name, description)

        # All checks are first initialized as 'pending' in the first patch set,
        # but if a test case submits a result for an individual patch (that is
        # not patch 0) the 'pending' status will never get cleared. Take care
        # of this automatically by submitting the same result to patch 0.
        if patch != cls.patchwork[0]:
            cls.patchwork.post_result(cls.patchwork[0],
                                                patchwork_state(verdict),
                                                name, description)

        cls.ldebug("Submit result\n%s" % pw_output)

    def run_cmd(self, *args, timeout=None, **kwargs):
        """ Run command and return return code, stdout and stderr """

        cmd = []
        cmd.extend(args)
        cmd_str = "{}".format(" ".join(str(w) for w in cmd))
        self.linfo("CMD: %s" % cmd_str)

        stdout = ""
        try:
            proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL,
                                bufsize=1,
                                universal_newlines=True,
                                cwd=self.src_dir,
                                **kwargs)
        except OSError as e:
            self.lerror("ERROR: failed to run cmd: %s" % e)
            return (-1, None, None)

        for line in proc.stdout:
            self.ldebug(line.rstrip('\n'))
            stdout += line

        # stdout is consumed in previous line. so, communicate() returns empty
        try:
            _, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            self.lerror("ERROR: failed to run cmd after timeout: %s" % e)
            proc.kill()
            proc.communicate()
            return (-1, None, None)

        self.ldebug(">> STDERR\n{}".format(stderr))

        return (proc.returncode, stdout, stderr)

class PatchworkSetup(CiBase):
    """
        Only used to initialize the patchwork object. If this is being run
        without an associated patchwork series it will be skipped and any tests
        depending on 'patchwork' will also be skipped.
    """
    name = "patchwork"
    display_name = "Patchwork Setup"
    desc = "Setup Patchwork object"
    user = 0

    def config(self):
        if not self.settings:
            return

        if 'user' in self.settings:
            self.user = int(self.settings['user'])

    def run(self):
        self.config()

        self.ldebug(self.user)
        self.ldebug(self.args.repo)
        self.ldebug(self.args.pr_num)

        if not self.user or not self.args.repo or not self.args.pr_num:
            # 'fetch' behaves differently depending on if patchwork is used or
            # not but the patchwork object must be initialized prior to fetch.
            # Since fetch/checkpath/gitlint check for self.patchwork its safe to
            # signal success so these tests get run.
            self.success()

        try:
            CiBase.patchwork = Patchwork(self.user, self.args.repo, self.args.pr_num)
        except Exception as e:
            self.ldebug("Unable to find matching patchwork entry, skipping")
            self.success()
            return

        # Initialize as pending
        for t in CiBase.suite.values():
            if self.args.external_trigger and t.ext_skip_pending:
                continue

            t.submit_result(Verdict.PENDING)

        self.success()

class FetchPR(CiBase):
    name = "fetch"
    display_name = "Fetch PR"
    desc = "Fetch the PR commits for this CI run"
    depends = ['patchwork']
    ext_skip_pending = True

    def cmd_failed(self, stderr):
        self.lerror("Failed to fetch the PR commits. error=%s" % stderr)
        self.submit_result(Verdict.FAIL, description="Fetch PR - FAIL: " + stderr)
        self.add_failure_end_test(stderr)

    def run(self):
        # Most other tests depend on fetch, so don't skip/fail this one even
        # if patchwork isn't being used.
        if not self.patchwork or self.args.external_trigger:
            self.ldebug("Running without patches, skipping PR fetch")
            self.success()

        (ret, stdout, stderr) = self.run_cmd("git", "fetch", "origin", "pull/%d/head:pr" % self.args.pr_num)
        if ret:
            self.cmd_failed(stderr)

        (ret, stdout, stderr) = self.run_cmd("git", "checkout", "pr")
        if ret:
            self.cmd_failed(stderr)

        self.ldebug("output>>\n%s" % stdout)

        self.submit_result(Verdict.PASS)
        self.success()

class CheckPatch(CiBase):
    name = "checkpatch"
    display_name = "CheckPatch"
    desc = "Run checkpatch.pl script with rule in .checkpatch.conf"
    checkpatch_pl = '/usr/bin/checkpatch.pl'
    no_sob = False
    depends = ['patchwork']
    ext_skip_pending = True

    def config(self):
        """
        Config the test cases.
        """
        if not self.settings:
            return

        if 'bin_path' in self.settings:
            self.checkpatch_pl = path_resolve(self.settings['bin_path'])

        if 'no_signoff' in self.settings:
            self.no_sob = self.settings['no_signoff'] == 'yes'

        self.ldebug("checkpatch_pl = %s" % self.checkpatch_pl)

    def run(self):
        if not self.patchwork or self.args.external_trigger:
            self.skip('Patchwork not being used, skipping')

        self.ldebug("##### Run CheckPatch Test #####")

        self.config()

        # Use patches from patchwork
        for patch in self.patchwork:
            self.ldebug("patch id: %d" % patch['id'])

            # Run checkpatch
            (output, error) = self.run_checkpatch(patch, no_sob=self.no_sob)

            # Failed / Warning
            if error != None:
                msg = "{}\n{}".format(patch['name'], error)
                if error.find("WARNING:") != -1:
                    if error.find("ERROR:") != -1:
                        self.submit_result(Verdict.FAIL, description=msg, patch=patch)
                    else:
                        self.submit_result(Verdict.WARNING, description=msg, patch=patch)
                else:
                    self.submit_result(Verdict.FAIL, description=msg, patch=patch)

                self.add_failure(msg)
                continue

            # Warning in output
            if output.find("WARNING:") != -1:
                self.submit_result(Verdict.WARNING, description=output, patch=patch)
                continue

            # Success
            self.submit_result(Verdict.PASS, patch=patch)

        # Overall status
        if self.verdict != Verdict.FAIL:
            self.success()

    def run_checkpatch(self, patch, no_sob=False):
        """
        Run checkpatch script with patch from the patchwork.
        It saves to file first and run checkpatch with the saved patch file.

        On success, it returns None.
        On failure, it returns the stderr output string
        """
        args = [ self.checkpatch_pl, '--no-tree' ]

        output = None
        error = None

        if no_sob:
            args.append('--no-signoff')

        # Save the patch content to file
        filename = patch.save()
        self.ldebug("Save patch: %s" % filename)

        args.append(filename)

        try:
            output = subprocess.check_output(args,
                                    stderr=subprocess.STDOUT,
                                    cwd='/tmp')
            output = output.decode("utf-8")

        except subprocess.CalledProcessError as ex:
            error = ex.output.decode("utf-8")
            self.lerror("checkpatch.pl returned with error")
            self.lerror("output: %s" % error)

        return (output, error)

class GitLint(CiBase):
    name = "gitlint"
    display_name = "GitLint"
    desc = "Run gitlint with rule in .gitlint"
    depends = ['patchwork']
    gitlint_config = '/.gitlint'
    ext_skip_pending = True

    def config(self):
        """
        Config the test cases.
        """
        if not self.settings:
            return

        if 'config_path' in self.settings:
            self.gitlint_config = path_resolve(self.settings['config_path'])

    def run(self):
        if not self.patchwork or self.args.external_trigger:
            self.skip('Patchwork not being used, skipping')

        self.ldebug("##### Run Gitlint v2 Test #####")

        self.config()

        # Use patches from patchwork
        for patch in self.patchwork:
            self.ldebug("patch id: %d" % patch['id'])

            # Run gitlint
            output = self.run_gitlint(patch)

            # Failed
            if output != None:
                msg = "{}\n{}".format(patch['name'], output)
                self.submit_result(Verdict.FAIL, description=msg, patch=patch)
                self.add_failure(msg)
                continue

            # Success
            self.submit_result(Verdict.PASS, patch=patch)

        # Overall status
        if self.verdict != Verdict.FAIL:
            self.success()

    def run_gitlint(self, patch):
        """
        Run checkpatch script with patch from the patchwork.
        It saves the commit message to the file first and run gitlint with it.

        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None

        # Save the patch commit message to file
        filename = patch.save_msg()
        self.ldebug("Save commit msg: %s" % filename)

        try:
            subprocess.check_output(('gitlint', '-C', self.gitlint_config,
                                        "--msg-filename", filename),
                                    stderr=subprocess.STDOUT,
                                    cwd=self.src_dir)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            self.lerror("gitlint returned error/warning")
            self.lerror("output: %s" % output)

        return output

class BuildSetup_ell(CiBase):
    name = "setupell"
    display_name = "Prep - Setup ELL"
    desc = "Clone, build, and install ELL"
    install = 'yes'
    depends = ['patchwork']

    def config(self):
        if self.settings:
            if 'install' in self.settings:
                self.install = self.settings['install']

        self.ldebug("install = %s" % self.install)

    def __init__(self, *args, **kwargs):
        super().__init__(src_dir=self.args.ell_path)

    def run(self):
        self.ldebug("##### Run Build: Setup ELL #####")

        self.config()

        # bootstrap-configure
        (ret, stdout, stderr) = self.run_cmd("./bootstrap-configure")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Setup ELL - Configuration FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # make
        (ret, stdout, stderr) = self.run_cmd("make", "-j4")
        if ret:
            self.submit_result(Verdict.FAIL,
                                description="Setup ELL - make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # install
        if self.install == 'yes':
            (ret, stdout, stderr) = self.run_cmd("make", "install")
            if ret:
                self.submit_result(Verdict.FAIL,
                                   description="Setup ELL - make install FAIL: " + stderr)
                self.add_failure_end_test(stderr)

        self.submit_result(Verdict.PASS)
        self.success()

class MakeDistcheck(CiBase):
    name = "makedistcheck"
    display_name = "Make Distcheck"
    desc = "Run distcheck to check the distribution"
    depends = ['setupell']
    isolate = True

    def run(self):
        self.ldebug("##### Run Make Distcheck Test #####")

        # Actual test starts:
        # Configure
        (ret, stdout, stderr) = self.run_cmd("./bootstrap-configure")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Make Distcheck Configure FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Make distcheck
        (ret, stdout, stderr) = self.run_cmd("fakeroot", "make",
                                                "distcheck", "-j4")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Make Distcheck Make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(Verdict.PASS)
        self.success()

class Build(CiBase):
    name = "build"
    display_name = "Build - Configure"
    desc = "Configure the BlueZ source tree"
    depends = ['setupell']
    inherit_src = 'fetch'

    def run(self):
        self.ldebug("##### Run Build Test #####")

        # bootstrap-configure
        (ret, stdout, stderr) = self.run_cmd("./bootstrap-configure")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Build Configuration FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(Verdict.PASS)
        self.success()

class BuildMake(CiBase):
    name = "buildmake"
    display_name = "Build - Make"
    desc = "Build the source tree"
    depends = ['build']
    inherit_src = 'build'

    def run(self):
        self.ldebug("##### Run Build Make Test #####")

        # make
        (ret, stdout, stderr) = self.run_cmd("make", "-j4")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(Verdict.PASS)
        self.success()

class MakeCheck(CiBase):
    name = "makecheck"
    display_name = "Make Check"
    desc = "Run \'make check\'"
    depends = ['buildmake']
    inherit_src = 'buildmake'

    def run(self):
        self.ldebug("##### Run MakeCheck Test #####")

        # Run make check. Assume the code is already configured and problem
        # to build.
        (ret, stdout, stderr) = self.run_cmd("make", "check")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Make Check FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(Verdict.PASS)
        self.success()

class MakeCheckValgrind(CiBase):
    name = "makecheckvalgrind"
    display_name = "Make Check w/Valgrind"
    desc = "Run \'make check\' with Valgrind"
    depends = ['setupell']

    def run(self):
        self.ldebug("##### Run MakeCheck w/ Valgrind Test #####")

        # bootstrap-configure without lsan and asan enabled
        (ret, stdout, stderr) = self.run_cmd("./bootstrap-configure",
                                        "--disable-lsan", "--disable-asan")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Build Configuration FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # make
        (ret, stdout, stderr) = self.run_cmd("make", "-j4")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        (ret, stdout, stderr) = self.run_cmd("make", "check")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Make Check FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(Verdict.PASS)
        self.success()

class BuildExtEll(CiBase):
    name = "build_extell"
    display_name = "Build w/ext ELL - Configure"
    desc = "Configure source with \'--enable-external-ell\' configuration"
    depends = ['setupell']

    def run(self):
        self.ldebug("##### Run Build w/external ell - configure Test #####")

        # bootstrap-configure
        (ret, stdout, stderr) = self.run_cmd("./bootstrap-configure",
                                        "--enable-external-ell")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Build External ELL FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(Verdict.PASS)
        self.success()

class BuildExtEllMake(CiBase):
    name = "build_extell_make"
    display_name = "Build w/ext ELL - Make"
    desc = "Build source with \'--enable-external-ell\' configuration"
    depends = ['build_extell']

    def run(self):
        self.ldebug("##### Run Build w/exteranl ell - make Test #####")

        # make
        (ret, stdout, stderr) = self.run_cmd("make", "-j4")
        if ret:
            self.submit_result(Verdict.FAIL,
                               description="Build Make with External ELL FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(Verdict.PASS)
        self.success()

class IncrementalBuild(CiBase):
    name = "incremental_build"
    display_name = "Incremental Build with patches"
    desc = "Incremental build per patch in the series"
    depends = ['setupell', 'patchwork']
    ext_skip_pending = True

    def run(self):
        if not self.patchwork or self.args.external_trigger:
            self.skip("Patchwork not being used, skipping")

        self.ldebug("##### Run Incremental Build Test #####")

        # If there is only one patch, no need to run and just return success
        if len(self.patchwork) == 1:
            self.ldebug("Only 1 patch and no need to run here")
            self.submit_result(Verdict.PASS,
                                description="Incremental build not run PASS")
            self.success()

        self.run_cmd('git', 'fetch')

        # Make the source base to workflow branch
        (ret, stdout, stderr) = self.run_cmd("git", "checkout",
                                                "origin/master")

        # Get the patch from the series, apply it and build.
        for i, patch in enumerate(self.patchwork):
            self.ldebug("patch id: %s" % patch['id'])
            self.ldebug("patch name: %s" % patch['name'])

            # Apply patch
            (output, error) = self.apply_patch(patch)
            if error != None:
                msg = "{}\n{}".format(patch['name'], error)
                self.submit_result(Verdict.FAIL,
                                   description="Applying Patch FAIL (patch %d): " % i + error,
                                   patch=patch)
                self.add_failure_end_test(msg)

            self.ldebug("Patch applied")

            # Configure
            (ret, stdout, stderr) = self.run_cmd("./bootstrap-configure")
            if ret:
                self.submit_result(Verdict.FAIL,
                                   description="Build Configuration FAIL (patch %d): " % i + stderr,
                                   patch=patch)
                self.add_failure_end_test(stderr)

            # Make
            (ret, stdout, stderr) = self.run_cmd("make", "-j4")
            if ret:
                self.submit_result(Verdict.FAIL,
                                   description="Make FAIL (patch %d):  " % i + stderr,
                                   patch=patch)
                self.add_failure_end_test(stderr)

            # Clean
            (ret, stdout, stderr) = self.run_cmd("make", "distclean")
            if ret:
                self.submit_result(Verdict.FAIL,
                                   description="Make Clean FAIL (patch %d): " % i + stderr,
                                   patch=patch)
                self.add_failure_end_test(stderr)

        # All patch passed the build test
        self.submit_result(Verdict.PASS)
        self.success()

    def apply_patch(self, patch):
        """
        Save the patch and apply to the source tree
        """

        output = None
        error = None

        # Save the patch content to file
        filename = patch.save()
        self.ldebug("Save patch: %s" % filename)

        try:
            output = subprocess.check_output(('git', 'am', filename),
                                             stderr=subprocess.STDOUT,
                                             cwd=self.src_dir)
            output = output.decode("utf-8")

        except subprocess.CalledProcessError as ex:
            error = ex.output.decode("utf-8")
            self.lerror("git am returned with error")
            self.lerror("output: %s" % error)

        return (output, error)

RESULTS_FORMAT = '''**{display_name}**
Test ID: {name}
Desc: {desc}
Duration: {elapsed:.2f} seconds
**Result: {status}**

'''

RESULTS_OUTPUT = '''Output:
```
{output}
```
'''

class GithubComment(CiBase):
    name = "githubcomment"
    display_name = "Comment to github"
    desc = "Add test results to the Github PR comments"
    depends = ['*', 'patchwork']
    submit_pw = False
    disable_src_dir = True

    def run(self):
        if not self.patchwork:
            self.skip('Patchwork not being used, skipping')

        comment = ''
        for test in self.suite.values():
            if '*' in test.depends or not test.submit_pw:
                continue

            comment += RESULTS_FORMAT.format(name=test.name,
                                            display_name=test.display_name,
                                            desc=test.desc,
                                            status=test.verdict.name,
                                            elapsed=test.elapsed())
            if test.output:
                comment += RESULTS_OUTPUT.format(output=test.output)

        self.patchwork.gh_pr.create_issue_comment(comment)

        self.success()

EMAIL_MESSAGE = '''
This is automated email and please do not reply to this email!

Dear submitter,

Thank you for submitting the patches to the {project} mailing list.
This is a CI test results with your patch series:
PW Link: {link}

---Test results---

{result}

---
Regards,
{project}
'''

class EmailResults(CiBase):
    name = "email"
    display_name = "Email results to author"
    desc = "Email test results to patch author"
    depends = ['*', 'patchwork']
    submit_pw = False
    disable_src_dir = True

    def send_email(self, sender, receiver, msg):
        """ Send email """

        if 'EMAIL_TOKEN' not in os.environ:
            self.skip("missing EMAIL_TOKEN. Skip sending email")

        try:
            session = smtplib.SMTP(self.settings['server'],
                                    int(self.settings['port']))
            session.ehlo()

            if 'starttls' not in self.settings or \
                            self.settings['starttls'] == 'yes':
                session.starttls()

            session.ehlo()
            session.login(sender, os.environ['EMAIL_TOKEN'])
            session.sendmail(sender, receiver, msg.as_string())
            self.linfo("Successfully sent email")

        except Exception as e:
            self.lerror("Exception: {}".format(e))
        finally:
            session.quit()

        self.linfo("Sending email done")

    def get_receivers(self, submitter):
        """
        Get list of receivers
        """

        self.ldebug("Get Receivers list")

        receivers = []

        maintainers = "".join(self.settings['maintainers'].splitlines()).split(",")
        receivers.extend(maintainers)

        if self.is_maintainer_only():
           return receivers
        else:
            receivers.append(submitter)

        return receivers

    def get_sender(self):
        """
        Get Sender from configuration
        """
        return self.settings['user']

    def get_default_to(self):
        """
        Get Default address which is a mailing list address
        """
        return self.settings['default-to']

    def is_maintainer_only(self):
        """
        Return True if it is configured to send maintainer-only
        """
        if 'only-maintainers' in self.settings and self.settings['only-maintainers'] == 'yes':
            return True

        return False

    def compose_email(self, title, body, submitter, msgid):
        """
        Compose and send email
        """

        receivers = self.get_receivers(submitter)
        sender = self.get_sender()

        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = ", ".join(receivers)
        msg['Subject'] = "RE: " + title

        # In case to use default-to address, set Reply-To to mailing list in case
        # submitter reply to the result email.
        if not self.is_maintainer_only():
            msg['Reply-To'] = self.get_default_to()

        # Message Header
        msg.add_header('In-Reply-To', msgid)
        msg.add_header('References', msgid)

        self.ldebug("Message Body: %s" % body)
        msg.attach(MIMEText(body, 'plain'))

        self.ldebug("Mail Message: {}".format(msg))

        # Send email
        self.send_email(sender, receivers, msg)

    def run(self):
        if not self.patchwork:
            self.skip('Patchwork not being used, skipping')

        results = ''
        for test in self.suite.values():
            if '*' in test.depends or not test.submit_pw:
                continue

            results += RESULTS_FORMAT.format(name=test.name,
                                            display_name=test.display_name,
                                            desc=test.desc,
                                            status=test.verdict.name,
                                            elapsed=test.elapsed())
            if test.output:
                results += RESULTS_OUTPUT.format(output=test.output)

        email = EMAIL_MESSAGE.format(
                            project=self.patchwork.series['project']['name'],
                            link=self.patchwork.series['web_url'],
                            result=results)
        self.compose_email(self.patchwork.series['name'], email,
                            self.patchwork.series['submitter']['email'],
                            self.patchwork[0]['msgid'])
        self.success()

if __name__ == '__main__':
    CiBase.run()
    CiBase.print_results()

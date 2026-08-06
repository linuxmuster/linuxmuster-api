import subprocess
from datetime import datetime
import dpath.util
import json
import re
import threading
import ast
import logging
from time import time

from .checks import check_tmp_dir
from .notifications import notify_completion


class SophomorixProcess(threading.Thread):
    """
    Worker for processing sophomorix commands.
    """

    def __init__(self, command, sensitive):
        self.stdout = None
        self.stderr = None
        self.command = command
        self.sensitive = sensitive
        threading.Thread.__init__(self)

    def run(self):
        p = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        self.stdout, self.stderr = p.communicate()


def parse_sophomorix_json(raw_output):
    """
    Extract the dict a sophomorix -j/-jj command wrote between its
    "# JSON-begin"/"# JSON-end" markers. Same quirks lmn_getSophomorixValue()
    always handled: ':null' isn't valid Python literal syntax so it's
    quoted first, and a command can emit more than one such block, of which
    only the first is used.

    :param raw_output: text containing a "# JSON-begin"/"# JSON-end" block
        (sophomorix -j/-jj writes it to stderr, not stdout)
    :type raw_output: basestring
    :return: parsed dict, or {} if the block was present but empty
    :rtype: dict
    :raises IndexError: no "# JSON-begin"/"# JSON-end" block found in raw_output
    """

    s = time()
    output = raw_output.replace(':null', ":\"null\"")
    output = output.replace(':null}', ":\"null\"}")
    output = output.replace(':null]', ":\"null\"]")

    output = output.replace('\n', '').split('# JSON-end')[0]
    output = output.split('# JSON-begin')[1]  # raises IndexError if the marker is missing
    output = re.sub('# JSON-begin', '', output)
    logging.debug(f"Sophomorix filter result time : {time()-s}")

    if not output:
        return {}

    s = time()
    jsonDict = ast.literal_eval(output)
    logging.debug(f"Sophomorix convert to dict time : {time()-s}")
    return jsonDict


def process_user(cmd, pid, command='', school='', caller='', notifications_config=None):
    """
    Run a (possibly multi-command, ';'-chained) sophomorix shell script in
    the background, tracking progress in /tmp/lmnapi/{pid}.sophomorix.status
    and, once done, best-effort notifying `notifications_config`'s callback
    (see utils/notifications.py) — a no-op if not configured.

    :param cmd: shell script to run (each sub-command already redirects its
        own output to /tmp/lmnapi/{pid}.sophomorix.log)
    :type cmd: basestring
    :param pid: job id, used for both the status/log file names
    :type pid: basestring
    :param command: sophomorix command(s) actually run, for the notification body
    :type command: basestring
    :param school: school the job ran for, for the notification body
    :type school: basestring
    :param caller: cn of the admin who triggered the job, for the notification body
    :type caller: basestring
    :param notifications_config: the `notifications:` section of config.yml
    :type notifications_config: dict
    """

    check_tmp_dir()
    statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"
    logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"

    start = datetime.now().strftime("%d %b %Y %H:%M:%S")
    with open(statuspath, 'w') as status:
        status.write(f"Process {pid} was started at {start} and is still running.")

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env={'LC_ALL': 'C'})
    stdout, stderr = p.communicate()

    now = datetime.now().strftime("%d %b %Y %H:%M:%S")
    with open(statuspath, 'w') as status:
        status.write(f"Process {pid} was started at {start} and was completed at {now}")

    try:
        with open(logpath, 'r') as f:
            log = f.read()
    except OSError:
        log = ''

    if command == 'sophomorix-check' and log:
        # -jj's JSON payload lands on stderr, combined into logpath via the
        # script's own '2>&1' redirect. Replace the raw log with just the
        # parsed, filtered result — same as what the old synchronous
        # endpoint used to return directly, instead of leaving it to
        # whoever polls/gets notified to redo this themselves.
        try:
            results = parse_sophomorix_json(log)
            if "CHECK_RESULT" in results:
                if "UPDATE" in results["CHECK_RESULT"] and "KILL" in results["CHECK_RESULT"]:
                    for user_update in tuple(results["CHECK_RESULT"]["UPDATE"]):
                        if user_update in results["CHECK_RESULT"]["KILL"]:
                            del results["CHECK_RESULT"]["UPDATE"][user_update]
            log = json.dumps(results)
            with open(logpath, 'w') as f:
                f.write(log)
        except (IndexError, SyntaxError, ValueError) as e:
            logging.warning(f"Job {pid}: could not parse sophomorix-check output as JSON, leaving raw log as-is: {e}")

    notify_completion(
        notifications_config,
        job_id=pid,
        command=command,
        school=school,
        caller=caller,
        status='success' if p.returncode == 0 else 'failed',
        exit_code=p.returncode,
        started_at=start,
        completed_at=now,
        log=log,
    )

def lmn_getSophomorixValue(sophomorixCommand, jsonpath, ignoreErrors=False, sensitive=False):
    """
    Connector to all sophomorix commands. Run a sophomorix command with -j
    option (output as json) through a SophomorixProcess and parse the results.

    :param sophomorixCommand: Command with options to run
    :type sophomorixCommand: list
    :param jsonpath: Key to search in the resulted dict, e.g. /USERS/doe
    :type jsonpath: string
    :param ignoreErrors: Quiet mode
    :type ignoreErrors: bool
    :return: Whole output or key if jsonpath is defined
    :rtype: dict or value (list, dict, integer, string)
    """

    # New Thread for one process to avoid conflicts
    s = time()
    t = SophomorixProcess(sophomorixCommand, sensitive=sensitive)
    t.daemon = True
    t.start()
    t.join()
    logging.debug(f"Sophomorix command time : {time()-s}")

    try:
        jsonDict = parse_sophomorix_json(t.stderr.decode("utf8"))
    except IndexError:
        raise Exception(f"A problem occur with sophomorix, full output is: {t.stdout}{t.stderr}")

    # Without key, simply return the dict
    if jsonpath == '':
        return jsonDict

    if ignoreErrors is False:
        try:
            s = time()
            resultString = dpath.util.get(jsonDict, jsonpath)
            logging.debug(f"Sophomorix search in dict time : {time()-s}")
        except Exception as e:
            raise Exception(
                'Sophomorix Value error !\n\n'
                f'Either sophomorix field does not exist or user does not have sufficient permissions:\n'
                f'Error Message: {e}\n'
                f'Dictionary we looked for information:\n'
                f'{jsonDict}'
            )
    else:
        resultString = dpath.util.get(jsonDict, jsonpath)
    return resultString


import subprocess
import dpath.util
import re
import threading
import ast
import logging
from time import time

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

    # Cleanup stderr output
    # output = t.stderr.replace(':null,', ":\"null\",")
    # TODO: Maybe sophomorix should provide the null value  in  a python usable format
    s = time()
    output = t.stderr.decode("utf8").replace(':null', ":\"null\"")
    output = output.replace(':null}', ":\"null\"}")
    output = output.replace(':null]', ":\"null\"]")


    # Some commands get many dicts, we just want the first
    output = output.replace('\n', '').split('# JSON-end')[0]
    output = output.split('# JSON-begin')[1]
    output = re.sub('# JSON-begin', '', output)
    logging.debug(f"Sophomorix filter result time : {time()-s}")

    # Convert str to dict
    jsonDict = {}
    if output:
        s = time()
        jsonDict = ast.literal_eval(output)
        logging.debug(f"Sophomorix convert to dict time : {time()-s}")

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


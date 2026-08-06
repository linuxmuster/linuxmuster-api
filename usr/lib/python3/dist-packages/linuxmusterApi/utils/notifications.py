import hashlib
import hmac
import json
import logging
import time
import uuid

import requests

from vars import VERSION

logger = logging.getLogger(__name__)


def notify_completion(notifications_config, *, job_id, command, school, caller, status, exit_code, started_at, completed_at, log):
    """
    Best-effort POST to the third-party callback URL configured under
    `notifications:` in config.yml, signalling that a background sophomorix
    job (check/add/update/kill) has finished.

    Never raises: an unconfigured or unreachable callback only logs a
    warning — it must not affect the sophomorix job it reports on, which has
    already completed by the time this runs.

    Header scheme:
      Content-Type: application/json
      x-webhook-key: <public identifier from config, NOT the HMAC secret>
      x-webhook-timestamp: <unix seconds, as a string>
      x-webhook-signature: sha256=<hex hmac-sha256 of "{timestamp}." + body>
      x-webhook-event-id: evt-<random>
      User-Agent: linuxmuster-api/v<VERSION>

    Mixing the timestamp into the signed payload (rather than signing the
    body alone) stops an intercepted request from being replayed verbatim
    with a still-valid signature.

    :param notifications_config: the `notifications:` section of config.yml
        (callback_url, key, secret, timeout) — a no-op if empty or missing
        callback_url.
    :type notifications_config: dict
    :param job_id: the pid used to poll GET .../status/{pid}
    :type job_id: basestring
    :param command: sophomorix command(s) that were run, e.g. "sophomorix-check"
        or "sophomorix-add+sophomorix-update"
    :type command: basestring
    :param school: school the job ran for
    :type school: basestring
    :param caller: cn of the admin who triggered the job
    :type caller: basestring
    :param status: "success" or "failed"
    :type status: basestring
    :param exit_code: exit code of the job's (last) command
    :type exit_code: int
    :param started_at: human-readable start time
    :type started_at: basestring
    :param completed_at: human-readable completion time
    :type completed_at: basestring
    :param log: full captured output of the job
    :type log: basestring
    """

    if not notifications_config:
        return

    callback_url = notifications_config.get('callback_url')
    if not callback_url:
        return

    body = {
        'event': 'sophomorix.job.completed',
        'job_id': job_id,
        'command': command,
        'school': school,
        'caller': caller,
        'status': status,
        'exit_code': exit_code,
        'started_at': started_at,
        'completed_at': completed_at,
        'log': log,
    }
    payload = json.dumps(body).encode('utf-8')

    timestamp = str(int(time.time()))
    secret = notifications_config.get('secret', '').encode('utf-8')
    signature = hmac.new(secret, f"{timestamp}.".encode('utf-8') + payload, hashlib.sha256).hexdigest()

    headers = {
        'Content-Type': 'application/json',
        'x-webhook-key': notifications_config.get('key', ''),
        'x-webhook-timestamp': timestamp,
        'x-webhook-signature': f'sha256={signature}',
        'x-webhook-event-id': f'evt-{uuid.uuid4().hex[:12]}',
        'User-Agent': f'linuxmuster-api/v{VERSION}',
    }

    try:
        requests.post(callback_url, data=payload, headers=headers, timeout=notifications_config.get('timeout', 5))
    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not notify completion of job {job_id} at {callback_url}: {e}")

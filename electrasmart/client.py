import os
import json
import random
from pprint import pformat

import requests
import logging

logger = logging.getLogger(__name__)


class ElectraAPI:
    URL = "https://app.ecpiot.co.il/mobile/mobilecommand"
    HEADERS = {'user-agent': 'Electra Client'}

    MOCK_OS_DATA = {
        "os": "android",
        "osver": "M4B30Z",
    }

    @classmethod
    def post(cls, cmd, data, sid=None, os_details=False):
        if os_details:
            data = data.copy()
            data.update(cls.MOCK_OS_DATA)
        random_id = random.randint(1000, 1999)
        post_data = dict(
            pvdid=1,
            id=random_id,
            sid=sid,
            cmd=cmd,
            data=data
        )
        logger.debug(f"Posting request\nid: {random_id}\nurl: {cls.URL}\nheaders: {cls.HEADERS}\n"
                     f"post json data:\n{pformat(post_data)}")
        try:
            response = requests.post(
                cls.URL,
                headers=cls.HEADERS,
                json=post_data,
            )
            j = response.json()
        except:
            logger.exception("ElectraAPI: Exception caught when posting to cloud service")
            raise
        logger.debug(f"Response received (id={random_id}):\n{pformat(j)}")
        try:
            assert j['status'] == 0, "invalid status returned from command"
            assert j['data']['res'] == 0, "invalid res returned from command"
        except:
            logger.exception(f"Error status when posting command")
            raise
        return j['data']


def generate_token(phone):
    """
    Generate an authentication pair (imei & token) to be used by the AC class
    :param phone: a string of digits (e.g. '0524001234')

    :return: imei, token
    """
    # generate a random imei with a valid prefix (note: this might not be checked today, but just in case)
    imei = f'2b950000{random.randint(10**7, 10**8-1)}'
    ElectraAPI.post("SEND_OTP", dict(
        imei=imei,
        phone=phone,
    ))
    otp = input(f"Please enter the OTP password received at {phone}: ")
    result = ElectraAPI.post(
        "CHECK_OTP",
        dict(
            imei=imei,
            phone=phone,
            code=otp
        ),
        os_details=True
    )
    # note: the result also includes a sid, but we throw it away, and regenerate one later from the token when needed
    token = result['token']
    return imei, token


def generate_sid(imei, token):
    result = ElectraAPI.post(
        'VALIDATE_TOKEN',
        dict(
            imei=imei,
            token=token,
        ),
        os_details=True
    )
    return result['sid']


def get_devices(imei, token):
    sid = generate_sid(imei, token)
    result = ElectraAPI.post("GET_DEVICES", {}, sid)
    assert "devices" in result and len(result["devices"]), "no devices found for this account"
    return result["devices"]


class AC:
    def __init__(self, imei, token, ac_id, sid=None, strict_mode=False, baseline_status=None):
        self.imei = imei
        self.token = token
        self.ac_id = ac_id
        self.sid = sid
        if strict_mode:
            self.baseline_status = baseline_status or default_example_status_path()
        else:
            self.baseline_status = None

    def _post(self, cmd, data, os_details=False):
        return ElectraAPI.post(cmd, data, self.sid, os_details)

    def status(self, *, check=False):
        r = self._post('GET_LAST_TELEMETRY', dict(
            id=self.ac_id,
            commandName='OPER,DIAG_L2,HB'
        ))
        cj = r["commandJson"]
        status = {k: self._parse_status_group(v) for k, v in cj.items()}
        if check:
            self.check_status(status)
        return status

    @classmethod
    def _parse_status_group(cls, v):
        if v is None or v == 'null' or v == 'None' or not v:
            return None
        return json.loads(v)

    ALLOWED_STATUS_VARIATIONS = {
        'OPER': ['AC_MODE', 'FANSPD', 'SPT', 'AC_STSRC']
    }

    def check_status(self, status):
        if self.baseline_status is None:
            # basline check not available (i.e. non-strict mode)
            return
        baseline_status = json.load(open(self.baseline_status, "r"))
        assert status.keys() == baseline_status.keys(), "different keys"
        for k, s1 in status.items():
            assert list(s1.keys()) == [k], f"expected ['{k}'] to have one '{k}' key"
            s2 = s1[k]
            assert s2.keys() == baseline_status[k][k].keys(), f"different keys in ['{k}']['{k}']"
            if k == 'DIAG_L2':
                continue
            for k2, v2 in s2.items():
                if k2 in self.ALLOWED_STATUS_VARIATIONS.get(k, []):
                    continue
                ref = baseline_status[k][k][k2]
                assert v2 == ref, f"mismatch in ['{k}']['{k}']['{k2}']: {repr(v2)} vs {repr(ref)}"

    def renew_sid(self):
        self.sid = generate_sid(self.imei, self.token)
        logger.debug(f"renewed sid: {self.sid}")
        return self.sid

    def modify_oper(self, *, ac_mode=None, fan_speed=None, temperature=None, ac_stsrc='WI-FI', auto_on_off=True):
        status = self.status(check=True)
        new_oper = status['OPER']['OPER'].copy()
        if ac_mode is not None:
            new_oper['AC_MODE'] = ac_mode
        if fan_speed is not None:
            new_oper['FANSPD'] = fan_speed
        if temperature is not None:
            if 'SPT' in new_oper:
                temperature = int(temperature) if isinstance(new_oper['SPT'], int) else str(temperature)
            new_oper['SPT'] = temperature
        if ac_stsrc is not None and "AC_STSRC" in new_oper:
            new_oper['AC_STSRC'] = ac_stsrc
        if auto_on_off:
            if 'TURN_ON_OFF' in new_oper and ac_mode is not None:
                if ac_mode == "STBY":
                    new_oper['TURN_ON_OFF'] = "OFF"
                else:
                    new_oper['TURN_ON_OFF'] = "ON"
        self._post('SEND_COMMAND', dict(
            id=self.ac_id,
            commandJson=json.dumps({'OPER': new_oper})
        ))

    def turn_off(self):
        self.modify_oper(ac_mode='STBY')

    def cool_24_auto(self):
        self.modify_oper(ac_mode='COOL', fan_speed='AUTO', temperature=24)

    def fan_high(self):
        self.modify_oper(ac_mode='FAN', fan_speed='HIGH')

    def cool_26_low(self):
        self.modify_oper(ac_mode='COOL', fan_speed='LOW', temperature=26)


def default_example_status_path():
    return os.path.join(os.path.dirname(__file__), "example_status.json")

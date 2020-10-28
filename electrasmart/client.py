import json
import random
from pprint import pformat
from contextlib import contextmanager

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
    def __init__(self, imei, token, ac_id, sid=None):
        self.imei = imei
        self.token = token
        self.ac_id = ac_id
        self.sid = sid
        self._status = None
        self._model = None

    def renew_sid(self):
        self.sid = generate_sid(self.imei, self.token)
        logger.info(f"renewed sid: {self.sid}")

    def update_status(self):
        self._status = self._fetch_status()

    @property
    def status(self):
        if self._status is None:
            return None
        return DeviceStatusAccessor(self._status, self.model)

    def _fetch_status(self):
        r = self._post('GET_LAST_TELEMETRY', dict(
            id=self.ac_id,
            commandName='OPER,DIAG_L2,HB'
        ))
        cj = r["commandJson"]
        status = {k: self._parse_status_group(v) for k, v in cj.items()}
        return status

    @classmethod
    def _parse_status_group(cls, v):
        if v is None or v == 'null' or v == 'None' or not v:
            return None
        return json.loads(v)

    @contextmanager
    def _modify_oper_and_send_command(self):
        self.update_status()
        new_oper = self.status.raw['OPER']['OPER'].copy()
        # make any needed modifications inplace within the context
        yield new_oper
        self._post('SEND_COMMAND', dict(
            id=self.ac_id,
            commandJson=json.dumps({'OPER': new_oper})
        ))

    def modify_oper(self, *, ac_mode=None, fan_speed=None, temperature=None, ac_stsrc='WI-FI'):
        with self._modify_oper_and_send_command() as oper:
            if ac_mode is not None:
                if self.model.on_off_flag:
                    if ac_mode == 'STBY':
                        # in models with on-off flag, we don't set ac_mode to standby, but turn the flag off instead
                        oper['TURN_ON_OFF'] = "OFF"
                    else:
                        # similarly, we must turn on the flag when we set ac mode
                        oper['AC_MODE'] = ac_mode
                        oper['TURN_ON_OFF'] = "ON"
                else:
                    oper['AC_MODE'] = ac_mode
            if fan_speed is not None:
                oper['FANSPD'] = fan_speed
            if temperature is not None:
                if 'SPT' in oper:
                    temperature = int(temperature) if isinstance(oper['SPT'], int) else str(temperature)
                oper['SPT'] = temperature
            if ac_stsrc is not None and "AC_STSRC" in oper:
                oper['AC_STSRC'] = ac_stsrc

    def turn_off(self):
        with self._modify_oper_and_send_command() as oper:
            if self.model.on_off_flag:
                oper['TURN_ON_OFF'] = 'OFF'
            else:
                oper['AC_MODE'] = 'STBY'

    @property
    def model(self):
        if self._model is None:
            if self._status is None:
                self._fetch_status()
            self._model = ACModel(self._status)
        return self._model

    def _post(self, cmd, data, os_details=False):
        return ElectraAPI.post(cmd, data, self.sid, os_details)


class ACModel:
    """Accessor to specific AC model characteristics
    """
    def __init__(self, status):
        self.on_off_flag = 'TURN_ON_OFF' in status['OPER']['OPER']


class DeviceStatusAccessor:
    """Accessor to device status
    """
    def __init__(self, status, ac_model):
        self.status = status
        self.ac_model = ac_model

    @property
    def _operoper(self):
        return self.status.get("OPER", {}).get("OPER", {})

    @property
    def raw(self):
        return self.status

    @property
    def is_on(self):
        if self.ac_model.on_off_flag:
            return self.status['OPER']['OPER']['TURN_ON_OFF'] != 'OFF'
        else:
            return self.status['OPER']['OPER']['AC_MODE'] != 'STBY'

    @property
    def fan_speed(self):
        return self._operoper.get("FANSPD", 'OFF') if self.is_on else 'OFF'

    @property
    def ac_mode(self):
        return self._operoper.get("AC_MODE", "STBY") if self.is_on else 'STBY'

    @property
    def spt(self):
        return self._operoper.get("SPT")

    @property
    def current_temp(self):
        diag_l2 = self.status.get("DIAG_L2", {}).get("DIAG_L2", {})
        return diag_l2.get("I_CALC_AT") or diag_l2.get("I_RAT")

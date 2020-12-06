import os
import json
import random
from datetime import datetime
from pprint import pformat

import requests
import logging

logger = logging.getLogger(__name__)


class ElectraAPI:
    URL = "https://app.ecpiot.co.il/mobile/mobilecommand"
    HEADERS = {"user-agent": "Electra Client"}

    MOCK_OS_DATA = {
        "os": "android",
        "osver": "M4B30Z",
    }

    MIN_TIME_BETWEEN_SID_UPDATES = 60
    LAST_SID_UPDATE_DATETIME = None
    SID = None

    @classmethod
    def post(cls, cmd, data, sid=None, os_details=False, retry=False):
        if os_details:
            data = data.copy()
            data.update(cls.MOCK_OS_DATA)
        random_id = random.randint(1000, 1999)
        post_data = dict(pvdid=1, id=random_id, sid=sid, cmd=cmd, data=data)
        logger.debug(
            f"Posting request\nid: {random_id}\nurl: {cls.URL}\nheaders: {cls.HEADERS}\n"
            f"post json data:\n{pformat(post_data)}"
        )
        try:
            response = requests.post(
                cls.URL,
                headers=cls.HEADERS,
                json=post_data,
            )
            j = response.json()
        except:
            logger.exception(
                "ElectraAPI: Exception caught when posting to cloud service"
            )
            raise
        logger.debug(f"Response received (id={random_id}):\n{pformat(j)}")
        if retry:
            try:
                assert j["status"] == 0, "invalid status returned from command"
                assert j["data"]["res"] == 0, "invalid res returned from command"
            except:
                logger.exception(f"Error status when posting command")
                raise
        else:
            if j["status"] != 0 or j["data"] is None or j["data"]["res"] != 0:
                return False
        return j["data"]


def send_otp_request(phone):
    """
    Generate an imei to be used by the AC class and send an OTP code request
    :param phone: a string of digits (e.g. '0524001234')

    :return: imei
    """
    # generate a random imei with a valid prefix (note: this might not be checked today, but just in case)
    imei = f"2b950000{random.randint(10**7, 10**8-1)}"
    ElectraAPI.post(
        "SEND_OTP",
        dict(
            imei=imei,
            phone=phone,
        ),
    )
    return imei


def get_otp_token(imei, phone, otp):
    """
    Send a request to get a token by providing the received otp code from send_otp_request
    :param imei: a string (e.g. '0524001234')
    :param phone: a string of digits (e.g. '0524001234')
    :param otp: a string

    :return: imei, token
    """
    result = ElectraAPI.post(
        "CHECK_OTP", dict(imei=imei, phone=phone, code=otp), os_details=True
    )
    # note: the result also includes a sid, but we throw it away, and regenerate one later from the token when needed
    token = result["token"]
    return imei, token


def generate_sid(imei, token):
    result = ElectraAPI.post(
        "VALIDATE_TOKEN",
        dict(
            imei=imei,
            token=token,
        ),
        os_details=True,
    )
    return result["sid"]


def get_shared_sid(imei, token):
    date_now = datetime.now()
    if (
        ElectraAPI.SID is None
        or ElectraAPI.LAST_SID_UPDATE_DATETIME is None
        or date_diff_in_seconds(date_now, ElectraAPI.LAST_SID_UPDATE_DATETIME)
        > ElectraAPI.MIN_TIME_BETWEEN_SID_UPDATES
    ):
        ElectraAPI.SID = generate_sid(imei, token)
        ElectraAPI.LAST_SID_UPDATE_DATETIME = date_now
        logger.info(f"renewed shared sid: {ElectraAPI.SID}")
    return ElectraAPI.SID


def date_diff_in_seconds(dt2, dt1):
    timedelta = dt2 - dt1
    return timedelta.days * 24 * 3600 + timedelta.seconds


def get_devices(imei, token):
    sid = generate_sid(imei, token)
    result = ElectraAPI.post("GET_DEVICES", {}, sid, False, True)
    assert "devices" in result and len(
        result["devices"]
    ), "no devices found for this account"
    return result["devices"]


class AC:
    def __init__(
        self,
        imei,
        token,
        ac_id,
        sid=None,
        strict_mode=False,
        baseline_status=None,
        use_single_sid=False,
    ):
        self.imei = imei
        self.token = token
        self.ac_id = ac_id
        self.use_singe_sid = use_single_sid
        if not use_single_sid:
            self.sid = sid
        if strict_mode:
            self.baseline_status = baseline_status or default_example_status_path()
        else:
            self.baseline_status = None

    def _post_with_retry(self, cmd, data, os_details=False):
        res = self._post(cmd, data, os_details, False)
        if not res:
            self.renew_sid()
            return self._post(cmd, data, os_details, True)
        return res

    def _post(self, cmd, data, os_details=False, retry=False):
        return ElectraAPI.post(cmd, data, self._get_sid(), os_details, retry)

    def _get_sid(self):
        if self.use_singe_sid:
            return ElectraAPI.SID
        else:
            return self.sid

    def status(self, *, check=False):
        r = self._post_with_retry(
            "GET_LAST_TELEMETRY", dict(id=self.ac_id, commandName="OPER,DIAG_L2,HB")
        )

        cj = r["commandJson"]
        status = {k: self._parse_status_group(v) for k, v in cj.items()}
        if check:
            self.check_status(status)
        return status

    @classmethod
    def _parse_status_group(cls, v):
        if v is None or v == "null" or v == "None" or not v:
            return None
        return json.loads(v)

    ALLOWED_STATUS_VARIATIONS = {"OPER": ["AC_MODE", "FANSPD", "SPT", "AC_STSRC"]}

    def check_status(self, status):
        if self.baseline_status is None:
            # basline check not available (i.e. non-strict mode)
            return
        baseline_status = json.load(open(self.baseline_status, "r"))
        assert status.keys() == baseline_status.keys(), "different keys"
        for k, s1 in status.items():
            assert list(s1.keys()) == [k], f"expected ['{k}'] to have one '{k}' key"
            s2 = s1[k]
            assert (
                s2.keys() == baseline_status[k][k].keys()
            ), f"different keys in ['{k}']['{k}']"
            if k == "DIAG_L2":
                continue
            for k2, v2 in s2.items():
                if k2 in self.ALLOWED_STATUS_VARIATIONS.get(k, []):
                    continue
                ref = baseline_status[k][k][k2]
                assert (
                    v2 == ref
                ), f"mismatch in ['{k}']['{k}']['{k2}']: {repr(v2)} vs {repr(ref)}"

    def renew_sid(self):
        if self.use_singe_sid:
            self.sid = get_shared_sid(self.imei, self.token)
        else:
            self.sid = generate_sid(self.imei, self.token)
            logger.debug(f"renewed sid: {self.sid}")

    def modify_oper(
        self,
        *,
        ac_mode=None,
        fan_speed=None,
        temperature=None,
        ac_stsrc="WI-FI",
        auto_on_off=True,
    ):
        status = self.status(check=True)
        new_oper = status["OPER"]["OPER"].copy()
        if ac_mode is not None:
            new_oper["AC_MODE"] = ac_mode
        if fan_speed is not None:
            new_oper["FANSPD"] = fan_speed
        if temperature is not None:
            if "SPT" in new_oper:
                temperature = (
                    int(temperature)
                    if isinstance(new_oper["SPT"], int)
                    else str(temperature)
                )
            new_oper["SPT"] = temperature
        if ac_stsrc is not None and "AC_STSRC" in new_oper:
            new_oper["AC_STSRC"] = ac_stsrc
        if auto_on_off:
            if "TURN_ON_OFF" in new_oper and ac_mode is not None:
                if ac_mode == "STBY":
                    new_oper["TURN_ON_OFF"] = "OFF"
                else:
                    new_oper["TURN_ON_OFF"] = "ON"
        self._post_with_retry(
            "SEND_COMMAND",
            dict(id=self.ac_id, commandJson=json.dumps({"OPER": new_oper})),
        )

    def turn_off(self):
        self.modify_oper(ac_mode="STBY")

    def cool_24_auto(self):
        self.modify_oper(ac_mode="COOL", fan_speed="AUTO", temperature=24)

    def fan_high(self):
        self.modify_oper(ac_mode="FAN", fan_speed="HIGH")

    def cool_26_low(self):
        self.modify_oper(ac_mode="COOL", fan_speed="LOW", temperature=26)


def default_example_status_path():
    return os.path.join(os.path.dirname(__file__), "example_status.json")

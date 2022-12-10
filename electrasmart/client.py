import json
import random
from datetime import datetime
from pprint import pformat
from contextlib import contextmanager

import requests
import logging
import aiohttp
import asyncio

logger = logging.getLogger(__name__)


class ElectraAPI:
    URL = "https://app.ecpiot.co.il/mobile/mobilecommand"
    HEADERS = {"user-agent": "Electra Client"}

    MOCK_OS_DATA = {"os": "android", "osver": "M4B30Z"}

    MIN_TIME_BETWEEN_SID_UPDATES = 60
    LAST_SID_UPDATE_DATETIME = None
    SID = None

    @classmethod
    def post(cls, cmd, data, sid=None, os_details=False, is_second_try=False):
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
            response = requests.post(cls.URL, headers=cls.HEADERS, json=post_data)
            j = response.json()
        except:
            logger.exception(
                "ElectraAPI: Exception caught when posting to cloud service"
            )
            raise
        logger.debug(f"Response received (id={random_id}):\n{pformat(j)}")
        if is_second_try:
            try:
                assert j["status"] == 0, "invalid status returned from command"
                assert j["data"]["res"] == 0, "invalid res returned from command"
            except:
                logger.exception(f"Error status when posting command")
                raise
        else:
            if j["status"] != 0 or j["data"] is None or j["data"]["res"] != 0:
                raise cls.RenewSidAndRetryException(j)
        return j["data"]

    @classmethod
    async def async_post(cls, cmd, data, sid=None, os_details=False, is_second_try=False):
        if os_details:
            data = data.copy()
            data.update(cls.MOCK_OS_DATA)
        random_id = random.randint(1000, 1999)
        post_data = dict(pvdid=1, id=random_id, sid=sid, cmd=cmd, data=data)
        logger.debug(
            f"[ASYNC] Posting request\nid: {random_id}\nurl: {cls.URL}\nheaders: {cls.HEADERS}\n"
            f"[ASYNC] post json data:\n{pformat(post_data)}"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(cls.URL, headers=cls.HEADERS, json=post_data) as response:
                    j = await response.json(content_type=None)
        except:
            logger.exception(
                "[ASYNC] ElectraAPI: Exception caught when posting to cloud service"
            )
            raise
        logger.debug(f"[ASYNC] Response received (id={random_id}):\n{pformat(j)}")
        if is_second_try:
            try:
                assert j["status"] == 0, "invalid status returned from command"
                assert j["data"]["res"] == 0, "invalid res returned from command"
            except:
                logger.exception(f"Error status when posting command")
                raise
        else:
            if j["status"] != 0 or j["data"] is None or j["data"]["res"] != 0:
                raise cls.RenewSidAndRetryException(j)
        return j["data"]

    # raised upon failure in the first try of a post
    class RenewSidAndRetryException(Exception):
        def __init__(self, post_response):
            self.post_response = post_response
            super().__init__()

        @property
        def res_desc(self):
            resp = self.post_response or {}
            res_desc = resp.get("data", {}).get("res_desc")
            if res_desc is None:
                return "[result description was not provided in post response]"
            return res_desc


def send_otp_request(phone):
    """
    Generate an imei to be used by the AC class and send an OTP code request
    :param phone: a string of digits (e.g. '0524001234')

    :return: imei
    """
    # generate a random imei with a valid prefix (note: this might not be checked today, but just in case)
    imei = f"2b950000{random.randint(10**7, 10**8-1)}"
    ElectraAPI.post("SEND_OTP", dict(imei=imei, phone=phone))
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
        "VALIDATE_TOKEN", dict(imei=imei, token=token), os_details=True
    )
    return result["sid"]


async def async_generate_sid(imei, token):
    result = await ElectraAPI.async_post(
        "VALIDATE_TOKEN", dict(imei=imei, token=token), os_details=True
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


async def async_get_shared_sid(imei, token):
    date_now = datetime.now()
    if (
        ElectraAPI.SID is None
        or ElectraAPI.LAST_SID_UPDATE_DATETIME is None
        or date_diff_in_seconds(date_now, ElectraAPI.LAST_SID_UPDATE_DATETIME)
        > ElectraAPI.MIN_TIME_BETWEEN_SID_UPDATES
    ):
        ElectraAPI.SID = await async_generate_sid(imei, token)
        ElectraAPI.LAST_SID_UPDATE_DATETIME = date_now
        logger.info(f"renewed shared sid: {ElectraAPI.SID}")
    return ElectraAPI.SID


def date_diff_in_seconds(dt2, dt1):
    timedelta = dt2 - dt1
    return timedelta.total_seconds()


def get_devices(imei, token):
    sid = generate_sid(imei, token)
    result = ElectraAPI.post("GET_DEVICES", {}, sid, False, True)
    assert "devices" in result and len(
        result["devices"]
    ), "no devices found for this account"
    return result["devices"]


class AC:
    def __init__(self, imei, token, ac_id, sid=None, use_single_sid=False):
        self.imei = imei
        self.token = token
        self.ac_id = ac_id
        self.use_singe_sid = use_single_sid
        if not use_single_sid:
            self.sid = sid
        self._status = None
        self._model = None

    def renew_sid(self):
        try:
            if self.use_singe_sid:
                self.sid = get_shared_sid(self.imei, self.token)
            else:
                self.sid = generate_sid(self.imei, self.token)
                logger.debug(f"renewed sid: {self.sid}")
        except ElectraAPI.RenewSidAndRetryException as exc:
            raise Exception(f"Failed to renew sid: {exc.res_desc}")

    async def async_renew_sid(self):
        try:
            if self.use_singe_sid:
                self.sid = await async_get_shared_sid(self.imei, self.token)
            else:
                self.sid = await async_generate_sid(self.imei, self.token)
                logger.debug(f"renewed sid: {self.sid}")
        except ElectraAPI.RenewSidAndRetryException as exc:
            raise Exception(f"Failed to renew sid: {exc.res_desc}")

    def update_status(self):
        self._status = self._fetch_status()

    async def async_update_status(self):
        self._status = await self._async_fetch_status()

    @property
    def status(self):
        if self._status is None:
            return None
        return DeviceStatusAccessor(self._status, self.model)

    def _fetch_status(self):
        r = self._post_with_sid_check(
            "GET_LAST_TELEMETRY", dict(id=self.ac_id, commandName="OPER,DIAG_L2,HB")
        )
        cj = r["commandJson"]
        status = {k: self._parse_status_group(v) for k, v in cj.items()}
        return status

    async def _async_fetch_status(self):
        r = await self._async_post_with_sid_check(
            "GET_LAST_TELEMETRY", dict(id=self.ac_id, commandName="OPER,DIAG_L2,HB")
        )
        cj = r["commandJson"]
        status = {k: self._parse_status_group(v) for k, v in cj.items()}
        return status

    def _post_with_sid_check(self, cmd, data, os_details=False):
        try:
            return self._post(cmd, data, os_details, False)
        except ElectraAPI.RenewSidAndRetryException:
            self.renew_sid()
            return self._post(cmd, data, os_details, True)

    async def _async_post_with_sid_check(self, cmd, data, os_details=False):
        try:
            return await self._async_post(cmd, data, os_details, False)
        except ElectraAPI.RenewSidAndRetryException:
            await self.async_renew_sid()
            return await self._async_post(cmd, data, os_details, True)

    def _post(self, cmd, data, os_details=False, is_second_try=False):
        return ElectraAPI.post(cmd, data, self._get_sid(), os_details, is_second_try)

    async def _async_post(self, cmd, data, os_details=False, is_second_try=False):
        return await ElectraAPI.async_post(cmd, data, self._get_sid(), os_details, is_second_try)

    def _get_sid(self):
        if self.use_singe_sid:
            return ElectraAPI.SID
        else:
            return self.sid

    @classmethod
    def _parse_status_group(cls, v):
        if v is None or v == "null" or v == "None" or not v:
            return None
        return json.loads(v)

    @contextmanager
    def _modify_oper_and_send_command(self):
        self.update_status()
        new_oper = self.status.raw["OPER"]["OPER"].copy()
        # make any needed modifications inplace within the context
        yield new_oper
        self._post_with_sid_check(
            "SEND_COMMAND",
            dict(id=self.ac_id, commandJson=json.dumps({"OPER": new_oper})),
        )

    def modify_oper(
        self,
        *,
        ac_mode=None,
        fan_speed=None,
        temperature=None,
        ac_stsrc="WI-FI",
        shabat=None,
        ac_sleep=None,
        ifeel=None,
    ):
        with self._modify_oper_and_send_command() as oper:
            if ac_mode is not None:
                if self.model.on_off_flag:
                    if ac_mode == "STBY":
                        # in models with on-off flag, we don't set ac_mode to standby, but turn the flag off instead
                        oper["TURN_ON_OFF"] = "OFF"
                    else:
                        # similarly, we must turn on the flag when we set ac mode
                        oper["AC_MODE"] = ac_mode
                        oper["TURN_ON_OFF"] = "ON"
                else:
                    oper["AC_MODE"] = ac_mode
            if fan_speed is not None:
                oper["FANSPD"] = fan_speed
            if temperature is not None:
                if "SPT" in oper:
                    temperature = (
                        int(temperature)
                        if isinstance(oper["SPT"], int)
                        else str(temperature)
                    )
                oper["SPT"] = temperature
            if ac_stsrc is not None and "AC_STSRC" in oper:
                oper["AC_STSRC"] = ac_stsrc
            if shabat is not None and "SHABAT" in oper:
                oper["SHABAT"] = shabat
            if ac_sleep is not None and "SLEEP" in oper:
                oper["SLEEP"] = ac_sleep
            if ifeel is not None and "IFEEL" in oper:
                oper["IFEEL"] = ifeel

    def turn_off(self):
        with self._modify_oper_and_send_command() as oper:
            if self.model.on_off_flag:
                oper["TURN_ON_OFF"] = "OFF"
            else:
                oper["AC_MODE"] = "STBY"

    @property
    def model(self):
        if self._model is None:
            if self._status is None:
                self._fetch_status()
            self._model = ACModel(self._status)
        return self._model


class ACModel:
    """Accessor to specific AC model characteristics"""

    def __init__(self, status):
        self.on_off_flag = "TURN_ON_OFF" in status["OPER"]["OPER"]


class DeviceStatusAccessor:
    """Accessor to device status"""

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
            return self.status["OPER"]["OPER"]["TURN_ON_OFF"] != "OFF"
        else:
            return self.status["OPER"]["OPER"]["AC_MODE"] != "STBY"

    @property
    def fan_speed(self):
        return self._operoper.get("FANSPD", "OFF") if self.is_on else "OFF"

    @property
    def ac_mode(self):
        return self._operoper.get("AC_MODE", "STBY") if self.is_on else "STBY"

    @property
    def spt(self):
        return self._operoper.get("SPT")

    @property
    def current_temp(self):
        diag_l2 = self.status.get("DIAG_L2", {}).get("DIAG_L2", {})
        # different devices use different keys to represent the current temperature.
        # furthermore, on some devices, bizarre extreme values appear in some of the keys.
        # see for example https://github.com/yonatanp/electrasmart-custom-component/issues/8
        # so we look for the value in order of preference of keys, and also filter on sane range of values
        candidates = [diag_l2.get(key) for key in ["I_RAT", "I_CALC_AT", "I_RCT"]]
        candidates = [
            value
            for value in candidates
            if value is not None and -5 <= int(value) <= 42
        ]
        if len(candidates) == 0:
            # no idea what's the temperature
            return None
        return candidates[0]

    @property
    def shabat(self):
        return self._operoper.get("SHABAT")

    @property
    def sleep(self):
        return self._operoper.get("SLEEP")

    @property
    def ifeel(self):
        return self._operoper.get("IFEEL")

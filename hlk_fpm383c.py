"""
This module provides a class and some functions to interact with
the HLK-FPM383C fingerprint module.

The HLK-FPM383C fingerprint module is a fingerprint recognition
module that can store and match fingerprints. It uses UART communication
to send and receive data.
"""

import serial
import serial.tools.list_ports as list_ports
import re
import logging
from typing import Literal


def find_comm_ports(regex_pattern: str) -> list[tuple[str, str]]:
    """
    Find the communication ports that match the regex pattern.

    Parameters:
        regex_pattern: The regex pattern to match the port description.

    Returns:
        list: A list of tuples containing the port and description.

    Example:
        ```
        matched_ports = find_comm_ports(".*CH340.*")
        if len(matched_ports) == 0:
            print("No device found")
        else:
            port = matched_ports[0][0]
        ```
    """

    ports = list_ports.comports()
    matched_ports = []

    for port, desc, _ in ports:
        if re.search(regex_pattern, desc):
            matched_ports.append((port, desc))

    return matched_ports


def get_checksum(data: bytes) -> bytes:
    """
    Get the checksum of the data.

    The checksum is the two's complement of the sum of all bytes in the data.

    Parameters:
        data: The data to calculate the checksum.

    Returns:
        bytes: The checksum.
    """

    if not isinstance(data, bytes):
        raise TypeError("Data must be of type bytes or bytearray")

    sum_val = sum(data)
    checksum = ((~sum_val) + 1) & 0xFF
    return checksum.to_bytes(1, byteorder="big")


class RequestPacket:
    PACKET_HEADER = b"\xF1\x1F\xE2\x2E\xB6\x6B\xA8\x8A"

    def __init__(
        self, cmd: bytes, data: bytes = b"", passwd: bytes = b"\x00\x00\x00\x00"
    ) -> None:
        self.cmd = cmd
        self.data = data
        self.passwd = passwd

    def __str__(self) -> str:
        attr_str = ", ".join(f"{k}={v}" for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attr_str})"

    def to_bytes(self) -> bytes:
        # Get bytes of the content.
        content = self.passwd + self.cmd + self.data
        content_checksum = get_checksum(content)
        content += content_checksum

        # Get bytes of the header.
        content_len = len(content).to_bytes(2, byteorder="big")
        header = self.PACKET_HEADER + content_len
        header_checksum = get_checksum(header)
        header += header_checksum

        return header + content


class ResponsePacket:
    PACKET_HEADER = b"\xF1\x1F\xE2\x2E\xB6\x6B\xA8\x8A"

    def __init__(self, cmd: bytes, status: bytes, data: bytes) -> None:
        self.cmd = cmd
        self.status = status
        self.data = data

    def __str__(self) -> str:
        attr_str = ", ".join(f"{k}={v}" for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attr_str})"

    @staticmethod
    def validate_bytes(
        packet_bytes: bytes, passwd: bytes = b"\x00\x00\x00\x00"
    ) -> None:
        """
        Validate the response packet bytes.

        Parameters:
            packet_bytes: The response packet bytes.
            passwd: The communication password.
        """

        if not isinstance(packet_bytes, bytes):
            raise TypeError("Packet bytes must be of type bytes")
        if not isinstance(passwd, bytes):
            raise TypeError("Password must be of type bytes")

        # Validate checksum of the header.
        header_checksum = packet_bytes[10].to_bytes(1, byteorder="big")
        header_actual_checksum = get_checksum(packet_bytes[:10])
        if header_checksum != header_actual_checksum:
            raise ValueError("Header checksum mismatch in response packet")

        # Validate checksum of the content.
        content_checksum = packet_bytes[-1].to_bytes(1, byteorder="big")
        content_actual_checksum = get_checksum(packet_bytes[11:-1])
        if content_checksum != content_actual_checksum:
            raise ValueError("Content checksum mismatch in response packet")

        # Validate the start sequence in the header.
        header = packet_bytes[:8]
        if header != __class__.PACKET_HEADER:
            raise ValueError("Incorrect header in response packet")

        # Validate length of the content.
        content_len = int.from_bytes(packet_bytes[8:10], byteorder="big")
        content_actual_len = len(packet_bytes) - 11
        if content_len != content_actual_len:
            raise ValueError("Content length mismatch in response packet")

        # Validate password in the content.
        actual_passwd = packet_bytes[11:15]
        if actual_passwd != passwd:
            raise ValueError("Incorrect password in response packet")

    @staticmethod
    def from_bytes(
        packet_bytes: bytes, passwd: bytes = b"\x00\x00\x00\x00"
    ) -> "ResponsePacket":
        __class__.validate_bytes(packet_bytes, passwd)

        cmd = packet_bytes[15:17]
        status = packet_bytes[17:21]
        data = packet_bytes[21:-1]
        return __class__(cmd, status, data)

    @staticmethod
    def packet_size(data_size: int = 0) -> int:
        """
        Calculate the full packet size based on the data size.

        Parameters:
            data_size: The size of the data in the packet.

        Returns:
            int: The full packet size.
        """

        return 22 + data_size


class HLK_FPM383C:
    REGISTRATION_STATUS = {
        b"\x00\x00\x00\x00": "Ok",
        b"\x00\x00\x00\x03": "Registration command illegal",
        b"\x00\x00\x00\x04": "System busy",
        b"\x00\x00\x00\x05": "Miss fingerprint registration command",
        b"\x00\x00\x00\x06": "System software error",
        b"\x00\x00\x00\x07": "Hardware error",
        b"\x00\x00\x00\x08": "Finger detection exteeded time",
        b"\x00\x00\x00\x09": "Feature extraction failed",
        b"\x00\x00\x00\x0B": "Storage full",
        b"\x00\x00\x00\x0C": "Storage write error",
        b"\x00\x00\x00\x0D": "Storage read error",
        b"\x00\x00\x00\x0E": "Low image quality",
        b"\x00\x00\x00\x0F": "Fingerprint template repeat",
        b"\x00\x00\x00\x10": "Small fingerprint area",
        b"\x00\x00\x00\x11": "Finger moved too fast",
        b"\x00\x00\x00\x12": "Finger moved too slow",
        b"\x00\x00\x00\x15": "Force quit",
        b"\x00\x00\x00\xFF": "Other error",
    }

    def __init__(
        self,
        port: str,
        baudrate: int = 57600,
        password: bytes = b"\x00\x00\x00\x00",
    ) -> None:
        """
        Initialize the object.

        Parameters:
            port: The communication port of the fingerprint module.
            baudrate: The baudrate of the serial communication.
            password: The communication password of the fingerprint module.
        """

        self.port = port
        self.baudrate = baudrate
        self.passwd = password

        # Create logger.
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s.%(funcName)s - %(levelname)s - %(message)s"
        )

        # Add stream handler to logger.
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def init_comm(self) -> bool:
        """
        Initialize the serial communication with the fingerprint module.

        Returns:
            bool: True if successful, otherwise False.
        """

        try:
            self.comm = serial.Serial(self.port, self.baudrate)
            self.logger.info(f"Opened serial port {self.port}")
        except Exception as e:
            self.logger.error(f"Failed to open serial port {self.port}")
            self.logger.error(f"Error: {e}", exc_info=True)
            return False
        return True

    def close_comm(self) -> bool:
        """
        Close the serial communication with the fingerprint module.

        Returns:
            bool: True if successful, otherwise False.
        """

        try:
            self.comm.close()
            self.logger.info(f"Closed serial port {self.port}")
        except Exception as e:
            self.logger.error(f"Failed to close serial port {self.port}")
            self.logger.error(f"Error: {e}", exc_info=True)
            return False
        return True

    def _make_packet(self, cmd: bytes, data: bytes = b"") -> RequestPacket:
        return RequestPacket(cmd=cmd, data=data, passwd=self.passwd)

    def _send_packet(self, packet: RequestPacket) -> None:
        self.comm.write(packet.to_bytes())

    def _receive_packet(self, data_size: int = 0) -> ResponsePacket:
        packet_size = ResponsePacket.packet_size(data_size)
        packet_bytes = self.comm.read(size=packet_size)
        return ResponsePacket.from_bytes(packet_bytes, self.passwd)

    def _request(self, cmd: bytes, data: bytes = b"") -> RequestPacket | None:
        try:
            request_packet = self._make_packet(cmd=cmd, data=data)
            self._send_packet(request_packet)
            self.logger.debug(f"Sent request packet: {request_packet}")
        except Exception as e:
            self.logger.error("Failed to send request packet")
            self.logger.error(f"Error: {e}", exc_info=True)
            return None

        return request_packet

    def _response(
        self,
        data_size: int = 0,
        valid_cmd: bytes | None = None,
        valid_status: list[bytes] | bytes = b"\x00\x00\x00\x00",
    ) -> ResponsePacket | None:
        try:
            response_packet = self._receive_packet(data_size=data_size)
            self.logger.debug(f"Received response packet: {response_packet}")
            if valid_cmd is not None and response_packet.cmd != valid_cmd:
                raise ValueError(
                    f"Invalid command in response packet (does not match the command in request packet): {response_packet.cmd}"
                )
            if isinstance(valid_status, bytes):
                valid_status = [valid_status]
            if response_packet.status not in valid_status:
                raise ValueError(
                    f"Invalid status code in response packet: {response_packet.status}"
                )
        except Exception as e:
            self.logger.error("Failed to receive response packet")
            self.logger.error(f"Error: {e}", exc_info=True)
            return None

        return response_packet

    def _request_and_response(
        self,
        request_cmd: bytes,
        request_data: bytes = b"",
        response_data_size: int = 0,
        response_valid_status: list[bytes] | bytes = b"\x00\x00\x00\x00",
    ) -> ResponsePacket | None:
        request_packet = self._request(request_cmd, request_data)
        if request_packet is None:
            return None

        response_packet = self._response(
            data_size=response_data_size,
            valid_cmd=request_packet.cmd,
            valid_status=response_valid_status,
        )
        return response_packet

    def register_fingerprint_async(self, press_idx: int) -> bool:
        """
        Register fingerprint in asynchronous mode.

        User should be pressing finger on the sensor when sending this
        command. Otherwise, the registration will fail and may cause
        a blocking state. It is suggested to use the synchronous registration
        method.

        Parameters:
            press_idx: The index of the press.

        Returns:
            bool: True if the command was sent successfully, otherwise False.

        Example:
            ```
            press_idx = 1
            cur_progress = 0
            device.register_fingerprint_async(press_idx)
            while True:
                time.sleep(0.5)
                ret = device.check_registration_status()
                if ret is None:
                    continue
                if "progress" not in ret:
                    print("Registration failed")
                    break
                if ret["finished"]:
                    print("Registration finished")
                    break
                if ret["progress"] > cur_progress:
                    press_idx += 1
                    cur_progress = ret["progress"]
                    device.register_fingerprint_async(press_idx)
            ```
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x11",
            request_data=press_idx.to_bytes(1, byteorder="big"),
            response_valid_status=[b"\x00\x00\x00\x00", b"\x00\x00\x00\x04"],
        )
        if response is None:
            return False

        if response.status == b"\x00\x00\x00\x00":
            self.logger.info(
                f"Sent fingerprint registration command (press {press_idx})"
            )
            return True
        elif response.status == b"\x00\x00\x00\x04":
            self.logger.error(
                f"Sending fingerprint registration command (press {press_idx}) failed ({response.status})"
            )
            return False
        else:
            pass

    def check_registration_status(
        self,
    ) -> dict[str, bytes | str | int | bool] | None:
        """
        Check the status of the asynchronous fingerprint registration.

        After sending the registration command, call this method to check the
        registration status. Wait some time between the two calls, because
        the computation in the registration process may take some time.

        Returns:
            dict | None:
                A dictionary containing the registration status information.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x12",
            response_data_size=3,
            response_valid_status=[
                status for status in self.REGISTRATION_STATUS.keys()
            ],
        )
        if response is None:
            return None

        status_desc = self.REGISTRATION_STATUS[response.status]
        if response.status == b"\x00\x00\x00\x00":
            finger_id = int.from_bytes(response.data[:2], byteorder="big")
            progress = response.data[2]
            registration_finished = progress >= 100
            self.logger.info(
                f"Fingerprint registration status: finger_id={finger_id}, progress={progress}, finished={registration_finished}"
            )
            return {
                "status": response.status,
                "status_desc": status_desc,
                "finger_id": finger_id,
                "progress": progress,
                "finished": registration_finished,
            }
        else:
            self.logger.error(
                f"Last press registration failed ({response.status}): {status_desc}"
            )
            return {"status": response.status, "status_desc": status_desc}

    def save_template(self, finger_id_to_save: int) -> bool:
        """
        Save the fingerprint template to the specified finger ID, after
        the registration is finished.

        Parameters:
            finger_id_to_save: The finger ID to save the fingerprint template.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x13",
            request_data=finger_id_to_save.to_bytes(2, byteorder="big"),
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(
            f"Sent fingerprint template saving command (finger_id={finger_id_to_save})"
        )
        return True

    def check_template_saving_result(self) -> dict[str, bytes | str | int] | None:
        """
        Check the result of the fingerprint template saving command.

        Returns:
            dict | None:
                A dictionary containing the template saving result information.
                Returns None if error occurred.
        """

        RESPONSE_STATUS = {
            b"\x00\x00\x00\x00": "Ok",
            b"\x00\x00\x00\x04": "System busy",
            b"\x00\x00\x00\x05": "Miss template saving command",
            b"\x00\x00\x00\x06": "System software error",
            b"\x00\x00\x00\x07": "Hardware error",
            b"\x00\x00\x00\x09": "Feature extraction failed",
            b"\x00\x00\x00\x0B": "Storage full",
            b"\x00\x00\x00\x0C": "Storage write error",
            b"\x00\x00\x00\x0D": "Storage read error",
            b"\x00\x00\x00\x0E": "Low image quality",
            b"\x00\x00\x00\x0F": "Fingerprint template repeat",
            b"\x00\x00\x00\xFF": "Other error",
        }

        response = self._request_and_response(
            request_cmd=b"\x01\x14",
            response_data_size=2,
            response_valid_status=[status for status in RESPONSE_STATUS.keys()],
        )
        if response is None:
            return None

        status_desc = RESPONSE_STATUS[response.status]
        if response.status == b"\x00\x00\x00\x00":
            finger_id = int.from_bytes(response.data, byteorder="big")
            self.logger.info(f"Fingerprint template saved (finger_id={finger_id})")
            return {
                "status": response.status,
                "status_desc": status_desc,
                "finger_id": finger_id,
            }

        else:
            self.logger.error(
                f"Fingerprint template saving failed ({response.status}): {status_desc}"
            )
            return {"status": response.status, "status_desc": status_desc}

    def auto_register_and_save(
        self, finger_id: int | None = None, num_press: int = 6, need_lift: bool = True
    ) -> int | None:
        """
        Automatically register and save the fingerprint template (synchrounous method).

        Parameters:
            finger_id:
                The finger ID to save the fingerprint template. If None, the
                module will automatically assign a finger ID.
            num_press: The number of presses to register the fingerprint.
            need_lift: Whether to lift the finger between presses.

        Returns:
            int | None:
                The finger ID where the fingerprint template is saved. Returns
                None if error occurred.
        """

        if num_press < 1 or num_press > 6:
            raise ValueError("Number of presses must be between 1 and 6")

        num_press_bytes = num_press.to_bytes(1, byteorder="big")
        finger_id_bytes = (
            finger_id.to_bytes(2, byteorder="big") if finger_id else b"\xFF\xFF"
        )
        need_lift_bytes = int(need_lift).to_bytes(1, byteorder="big")
        data_bytes = need_lift_bytes + num_press_bytes + finger_id_bytes
        request = self._request(cmd=b"\x01\x18", data=data_bytes)
        if request is None:
            return None

        self.logger.info(
            f"Sent auto registration command (num_press={num_press}, finger_id={finger_id}, need_lift={need_lift})"
        )

        while True:
            response = self._response(
                data_size=4,
                valid_cmd=b"\x01\x18",
                valid_status=[status for status in self.REGISTRATION_STATUS.keys()],
            )
            if response is None:
                return None

            status_desc = self.REGISTRATION_STATUS[response.status]
            if response.status != b"\x00\x00\x00\x00":
                self.logger.error(
                    f"Auto registration failed ({response.status}): {status_desc}"
                )
                return None

            pressed_num = response.data[0]
            finger_id_to_save = int.from_bytes(response.data[1:3], byteorder="big")
            progress = response.data[3]
            if pressed_num == 255:
                self.logger.info(
                    f"Auto registration finished, saved to finger_id={finger_id_to_save}"
                )
                break
            self.logger.info(
                f"Auto registration status: pressed_num={pressed_num}, finger_id_to_save={finger_id_to_save}, progress={progress}"
            )

        return finger_id_to_save

    def confirm_registration(self) -> bool:
        response = self._request_and_response(
            request_cmd=b"\x01\x41",
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info("Sent confirm fingerprint registration command")
        return True

    def check_registration_confirmation_result(
        self,
    ) -> dict[str, bytes | str | int] | None:
        response = self._request_and_response(
            request_cmd=b"\x01\x42",
            response_data_size=6,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        result = bool.from_bytes(response.data[:2], byteorder="big")
        score = int.from_bytes(response.data[2:4], byteorder="big")
        matched_id = int.from_bytes(response.data[4:], byteorder="big")
        self.logger.info(
            f"Fingerprint registration confirmation result: result={result}, score={score}, matched_id={matched_id}"
        )
        return {"result": result, "score": score, "matched_id": matched_id}

    def _delete_template(
        self,
        cmd: bytes,
        mode: Literal["single", "all", "multi", "block"],
        finger_id: int | list[int] | None,
    ) -> bool:
        if mode == "single":
            if not isinstance(finger_id, int):
                raise ValueError("Finger ID must be an integer in single mode")
            mode_bytes = b"\x00"
            id_bytes = finger_id.to_bytes(2, byteorder="big")

        elif mode == "all":
            mode_bytes = b"\x01"
            id_bytes = b"\xFF\xFF"  # Placeholder, useless in this mode

        elif mode == "multi":
            if not (
                isinstance(finger_id, list | tuple)
                and len(finger_id) > 0
                and all(isinstance(id, int) for id in finger_id)
            ):
                raise ValueError("Finger ID must be a list of integers in multi mode")
            mode_bytes = b"\x02"
            id_bytes = len(finger_id).to_bytes(2, byteorder="big")
            for id in finger_id:
                id_bytes += id.to_bytes(2, byteorder="big")

        elif mode == "block":
            if not (
                isinstance(finger_id, list | tuple)
                and len(finger_id) == 2
                and all(isinstance(id, int) for id in finger_id)
            ):
                raise ValueError(
                    "Finger ID must be a list of two integers in block mode"
                )
            mode_bytes = b"\x03"
            first_id_bytes = finger_id[0].to_bytes(2, byteorder="big")
            last_id_bytes = finger_id[1].to_bytes(2, byteorder="big")
            id_bytes = first_id_bytes + last_id_bytes

        else:
            raise ValueError("Invalid mode")

        response = self._request_and_response(
            request_cmd=cmd,
            request_data=mode_bytes + id_bytes,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(
            f"Sent fingerprint template deletion command (mode={mode}, finger_id={finger_id})"
        )
        return True

    def delete_template_async(
        self,
        mode: Literal["single", "all", "multi", "block"] = "single",
        finger_id: int | list[int] | None = None,
    ) -> bool:
        """
        Delete fingerprint template in asynchronous mode.

        Parameters:
            mode: The deletion mode.
            finger_id:
                The finger ID to delete template.
                If mode is "single", this should be an integer.
                If mode is "multi", this should be a list of integers.
                If mode is "block", this should be a list of two integers.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        return self._delete_template(cmd=b"\x01\x31", mode=mode, finger_id=finger_id)

    def check_template_deletion_result(self) -> bool | None:
        """
        Check the result of the asynchronous template deletion command.

        After sending the deletion command, call this method to check the
        deletion result. Wait some time between the two calls, because the
        deletion process may take some time.

        Returns:
            bool | None:
                True if the deletion was successful, otherwise False.
                Returns None if error occurred.
        """

        RESPONSE_STATUS = {
            b"\x00\x00\x00\x00": "Ok",
            b"\x00\x00\x00\x01": "Unknown command",
            b"\x00\x00\x00\x02": "Command field length illegal",
            b"\x00\x00\x00\x03": "Command field illegal",
            b"\x00\x00\x00\x04": "System busy",
        }

        response = self._request_and_response(
            request_cmd=b"\x01\x32",
            response_valid_status=[status for status in RESPONSE_STATUS.keys()],
        )
        if response is None:
            return None

        status_desc = RESPONSE_STATUS[response.status]
        if response.status == b"\x00\x00\x00\x00":
            self.logger.info(f"Fingerprint template deleted successfully")
            return True
        else:
            self.logger.error(
                f"Fingerprint template deletion failed ({response.status}): {status_desc}"
            )
            return False

    def delete_template_sync(
        self,
        mode: Literal["single", "all", "multi", "block"] = "single",
        finger_id: int | list[int] | None = None,
    ) -> bool:
        """
        Delete fingerprint template in synchronous mode.

        Parameters:
            mode: The deletion mode.
            finger_id:
                The finger ID to delete template.
                If mode is "single", this should be an integer.
                If mode is "multi", this should be a list of integers.
                If mode is "block", this should be a list of two integers.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        return self._delete_template(cmd=b"\x01\x36", mode=mode, finger_id=finger_id)

    def match_fingerprint_async(self) -> bool:
        """
        Match fingerprint in asynchronous mode.

        User should be pressing finger on the sensor when sending this
        command. Otherwise, the matching will fail and may cause a blocking
        state. It is suggested to use the synchronous matching method.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x21",
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info("Sent fingerprint matching command")
        return True

    def _match_result(self, cmd: bytes) -> dict[str, bytes | str | bool | int] | None:
        RESPONSE_STATUS = {
            b"\x00\x00\x00\x00": "Ok",
            b"\x00\x00\x00\x04": "System busy",
            b"\x00\x00\x00\x05": "Miss fingerprint matching command",
            b"\x00\x00\x00\x06": "System software error",
            b"\x00\x00\x00\x07": "Hardware error",
            b"\x00\x00\x00\x08": "Finger detection exteeded time",
            b"\x00\x00\x00\x09": "Feature extraction failed",
            b"\x00\x00\x00\x0A": "Empty fingerprint template gallery",
            b"\x00\x00\x00\x0E": "Low image quality",
            b"\x00\x00\x00\x10": "Small fingerprint area",
            b"\x00\x00\x00\xFF": "Other error",
        }

        response = self._request_and_response(
            request_cmd=cmd,
            response_data_size=6,
            response_valid_status=[status for status in RESPONSE_STATUS.keys()],
        )
        if response is None:
            return None

        status_desc = RESPONSE_STATUS[response.status]
        if response.status == b"\x00\x00\x00\x00":
            result = bool.from_bytes(response.data[:2], byteorder="big")
            score = int.from_bytes(response.data[2:4], byteorder="big")
            matched_id = int.from_bytes(response.data[4:], byteorder="big")
            self.logger.info(
                f"Fingerprint matching result: result={result}, score={score}, matched_id={matched_id}"
            )
            return {
                "status": response.status,
                "status_desc": status_desc,
                "result": result,
                "score": score,
                "matched_id": matched_id,
            }
        else:
            self.logger.error(
                f"Fingerprint matching failed ({response.status}): {status_desc}"
            )
            return {"status": response.status, "status_desc": status_desc}

    def check_matching_result(self) -> dict[str, bytes | str | bool | int] | None:
        """
        Check the result of the asynchronous fingerprint matching.

        After sending the matching command, call this method to check
        the matching result. Wait some time between the two calls, because
        the computation in the matching process may take some time.

        Returns:
            dict | None:
                A dictionary containing the matching result information.
                Returns None if error occurred.
        """

        return self._match_result(cmd=b"\x01\x22")

    def match_fingerprint_sync(self) -> dict[str, bytes | str | bool | int] | None:
        """
        Match fingerprint in synchronous mode.

        Returns:
            dict | None:
                A dictionary containing the matching result information.
                Returns None if error occurred.
        """

        return self._match_result(cmd=b"\x01\x23")

    def cancel_registration_or_matching(self) -> bool:
        """
        Cancel the fingerprint registration or matching process.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x15",
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info("Sent fingerprint registration or matching cancel command")
        return True

    def update_stored_feature(self, finger_id: int) -> bool:
        response = self._request_and_response(
            request_cmd=b"\x01\x16",
            request_data=finger_id.to_bytes(2, byteorder="big"),
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(f"Sent update stored feature command (finger_id={finger_id})")
        return True

    def check_feature_updating_result(self) -> bool:
        response = self._request_and_response(
            request_cmd=b"\x01\x17",
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info("Sent check feature updating result command")
        return True

    def download_template_info(self, finger_id: int, template_size: int) -> bool:
        """
        Download the fingerprint template information to the module.

        Parameters:
            finger_id: The finger ID of the template.
            template_size: The size of the template in bytes.

        Returns:
            bool: True if the information was downloaded successfully, otherwise False.
        """

        id_bytes = finger_id.to_bytes(2, byteorder="big")
        size_bytes = template_size.to_bytes(2, byteorder="big")
        response = self._request_and_response(
            request_cmd=b"\x01\x51",
            request_data=id_bytes + size_bytes,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(
            f"Sent download template info command (finger_id={finger_id}, template_size={template_size} bytes)"
        )
        return True

    def download_template_data(self, frame_idx: int, frame_data: bytes) -> bool:
        """
        Download part of the fingerprint template data to the module.

        Parameters:
            frame_idx: The frame index of the template data.
            frame_data: The frame data to download.

        Returns:
            bool: True if the data was downloaded successfully, otherwise False.
        """

        if len(frame_data) > 128:
            raise ValueError("Frame data must be less than or equal to 128 bytes")

        idx_bytes = frame_idx.to_bytes(2, byteorder="big")
        response = self._request_and_response(
            request_cmd=b"\x01\x52",
            request_data=idx_bytes + frame_data,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(
            f"Dowloaded template data (frame_idx={frame_idx}, size={len(frame_data)} bytes)"
        )
        return True

    def download_template(self, finger_id: int, template: bytes) -> bool:
        """
        Download the fingerprint template to the module.

        Parameters:
            finger_id: The finger ID of the template.
            template: The template to download.

        Returns:
            bool: True if the template was downloaded successfully, otherwise False.
        """

        template_size = len(template)
        if template_size == 0:
            raise ValueError("Template size must be greater than 0")

        if not self.download_template_info(finger_id, template_size):
            return False

        for i in range(template_size // 128 + 1):
            if i < template_size // 128:
                frame_data = template[i * 128 : (i + 1) * 128]
            else:
                frame_data = template[i * 128 :]
            if not self.download_template_data(i, frame_data):
                return False

        self.logger.info(
            f"Downloaded template (finger_id={finger_id}, size={template_size} bytes)"
        )
        return True

    def upload_template_info(self, finger_id: int) -> int | None:
        """
        Upload the fingerprint template information from the module.

        Parameters:
            finger_id: The finger ID of the template.

        Returns:
            int | None: The size of the uploaded template. Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x53",
            request_data=finger_id.to_bytes(2, byteorder="big"),
            response_data_size=2,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        template_size = int.from_bytes(response.data, byteorder="big")
        self.logger.info(
            f"Uploaded template info (finger_id={finger_id}, template_size={template_size} bytes)"
        )
        return template_size

    def upload_template_data(self, frame_idx: int) -> tuple[int, bytes] | None:
        """
        Upload part of the fingerprint template data from the module.

        Parameters:
            frame_idx: The frame index of the template data.

        Returns:
            tuple | None:
                A tuple containing the uploaded frame index and frame data.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x54",
            request_data=frame_idx.to_bytes(2, byteorder="big"),
            response_data_size=130,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        uploaded_idx = int.from_bytes(response.data[:2], byteorder="big")
        frame_data = response.data[2:]
        self.logger.info(
            f"Uploaded template data (frame_idx={uploaded_idx}, size={len(frame_data)} bytes)"
        )
        return uploaded_idx, frame_data

    def upload_template(self, finger_id: int) -> bytes | None:
        """
        Upload the fingerprint template from the module.

        Parameters:
            finger_id: The finger ID of the template.

        Returns:
            bytes | None: The uploaded template. Returns None if error occurred.
        """

        template_size = self.upload_template_info(finger_id)
        if template_size is None:
            return None

        template = b""
        for i in range(template_size // 128 + 1):
            upload_data = self.upload_template_data(i)
            if upload_data is None:
                return None

            frame_idx, frame_data = upload_data
            if frame_idx != i:
                self.logger.error(
                    f"Frame index mismatch in uploaded template: expected={i}, actual={frame_idx}"
                )
                return None
            template += frame_data

        template = template[:template_size]
        self.logger.info(
            f"Uploaded template (finger_id={finger_id}, size={template_size} bytes)"
        )
        return template

    def detect_finger_pressed(self) -> bool | None:
        """
        Detect if the finger is pressed on the sensor.

        Returns:
            bool | None:
                True if the finger is pressed, otherwise False.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x35",
            response_data_size=1,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        pressed = bool(response.data)
        self.logger.info(f"Finger pressed: {pressed}")
        return pressed

    def check_finger_id_exists(self, finger_id: int) -> bool | None:
        """
        Check if the fingerprint ID registered in the module.

        Parameters:
            finger_id: The finger ID to check.

        Returns:
            bool | None:
                True if the finger ID registered, otherwise False.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x33",
            request_data=finger_id.to_bytes(2, byteorder="big"),
            response_data_size=3,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        exists = bool(response.data[0])
        response_id = int.from_bytes(response.data[1:], byteorder="big")
        if response_id != finger_id:
            self.logger.error(
                f"Finger ID mismatch: expected={finger_id}, actual={response_id}"
            )
            return None

        self.logger.info(f"Finger id={finger_id} exists: {exists}")
        return exists

    def get_stored_template_num(self) -> int | None:
        """
        Get the number of stored fingerprint templates.

        Returns:
            int | None:
                The number of stored fingerprint templates.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x02\x03",
            response_data_size=2,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        template_num = int.from_bytes(response.data, byteorder="big")
        self.logger.info(f"Stored fingerprint template number: {template_num}")
        return template_num

    def report_stored_templates(self) -> dict[str, int | list[int]] | None:
        """
        Report the stored fingerprint templates.

        Returns:
            dict | None:
                A dictionary containing the stored fingerprint templates
                information. Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x01\x34",
            response_data_size=66,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        capacity = int.from_bytes(response.data[:2], byteorder="big")
        stored_ids = []
        for i in range(64):
            info_byte = response.data[2 + i]
            for j in range(8):
                if info_byte & (1 << j):
                    stored_ids.append(i * 8 + j)

        self.logger.info(
            f"Total storage capacity: {capacity}, stored ids: {stored_ids}"
        )
        return {"capacity": capacity, "stored_ids": stored_ids}

    def reset_fp_module(self) -> bool:
        """
        Reset the fingerprint module.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        response = self._request_and_response(
            request_cmd=b"\x02\x02",
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info("Sent fingerprint module reset command")
        return True

    def get_gain(self) -> dict[str, int] | None:
        """
        Get the fingerprint gain settings.

        Returns:
            dict | None:
                A dictionary containing the gain settings.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x02\x09",
            response_data_size=3,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        shift, gain, pxl_ctrl = response.data[0], response.data[1], response.data[2]
        self.logger.info(
            f"Fingerprint gain: shift={shift}, gain={gain}, pxl_ctrl={pxl_ctrl}"
        )
        return {"shift": shift, "gain": gain, "pxl_ctrl": pxl_ctrl}

    def get_matching_threshold(self) -> int | None:
        """
        Get the fingerprint matching threshold.

        Returns:
            int | None:
                The fingerprint matching threshold.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x02\x0B",
            response_data_size=2,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        threshold = int.from_bytes(response.data, byteorder="big")
        self.logger.info(f"Fingerprint matching threshold: {threshold}")
        return threshold

    def set_finger_enroll_num(self, num: int) -> bool:
        """
        Set enroll number in asynchronous fingerprint registration.

        Parameters:
            num: The enroll number (1-6).

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        if num < 1 or num > 6:
            raise ValueError("Enroll number must be between 1 and 6")

        response = self._request_and_response(
            request_cmd=b"\x02\x0D",
            request_data=num.to_bytes(1, byteorder="big"),
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(f"Set fingerprint enroll number: {num}")
        return True

    def set_led(
        self,
        mode: Literal["off", "on", "touch", "pwm", "blink"],
        color: Literal[
            "none",
            "green",
            "red",
            "red_green",
            "blue",
            "red_blue",
            "green_blue",
            "red_green_blue",
        ],
        params: list[int] | None = None,
    ) -> bool:
        """
        Set the LED on the fingerprint module.

        Parameters:
            mode: The LED mode.
            color: The LED color.
            params: The parameters for the LED mode.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        MODES = {"off": 0, "on": 1, "touch": 2, "pwm": 3, "blink": 4}
        COLORS = {
            "none": 0,
            "green": 1,
            "red": 2,
            "red_green": 3,
            "blue": 4,
            "red_blue": 5,
            "green_blue": 6,
            "red_green_blue": 7,
        }

        if mode not in MODES:
            raise ValueError("Invalid mode")
        if color not in COLORS:
            raise ValueError("Invalid color")
        if mode in ["pwm", "blink"] and (params is None or len(params) != 3):
            raise ValueError(f"Mode {mode} requires 3 parameters")

        mode_byte = MODES[mode].to_bytes(1, byteorder="big")
        color_byte = COLORS[color].to_bytes(1, byteorder="big")
        if params is None:
            params = [0, 0, 0]
        param_bytes = b"".join(param.to_bytes(1, byteorder="big") for param in params)

        response = self._request_and_response(
            request_cmd=b"\x02\x0F",
            request_data=mode_byte + color_byte + param_bytes,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(f"Set LED: mode={mode}, color={color}, params={params}")
        return True

    def get_system_policy(self) -> dict[str, bool] | None:
        """
        Get the system policy settings.

        Returns:
            dict | None:
                A dictionary containing the system policy settings.
                Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x02\xFB",
            response_data_size=4,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        used_byte = response.data[3]
        check_repeated = bool(used_byte & (1 << 1))
        self_learn = bool(used_byte & (1 << 2))
        rotation360 = bool(used_byte & (1 << 4))
        self.logger.info(
            f"System policy: check_repeated={check_repeated}, self_learn={self_learn}, rotation360={rotation360}"
        )
        return {
            "check_repeated": check_repeated,
            "self_learn": self_learn,
            "rotation360": rotation360,
        }

    def set_system_policy(
        self,
        check_repeated: bool = True,
        self_learn: bool = True,
        rotation360: bool = True,
    ) -> bool:
        """
        Set the system policy settings.

        Parameters:
            check_repeated: Whether to check repeated fingerprints.
            self_learn: Whether to enable self-learning.
            rotation360: Whether to enable 360-degree rotation recognition.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        used_byte = 0
        used_byte |= int(check_repeated) << 1
        used_byte |= int(self_learn) << 2
        used_byte |= int(rotation360) << 4
        used_byte = used_byte.to_bytes(1, byteorder="big")
        unused_bytes = b"\x00\x00\x00"

        response = self._request_and_response(
            request_cmd=b"\x02\xFC",
            request_data=unused_bytes + used_byte,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(
            f"Set system policy: check_repeated={check_repeated}, self_learn={self_learn}, rotation360={rotation360}"
        )
        return True

    def get_fp_module_id(self) -> str | None:
        """
        Get the fingerprint module ID.

        Returns:
            str | None: The fingerprint module ID. Returns None if error occurred.
        """

        response = self._request_and_response(
            request_cmd=b"\x03\x01",
            response_data_size=16,
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return None

        module_id = response.data.decode("utf-8")
        self.logger.info(f"Fingerprint module ID: {module_id}")
        return module_id

    def check_connection(self) -> bool:
        """
        Check if the device is in connection.

        Returns:
            bool: True if the device is in connection, otherwise False.
        """

        response = self._request_and_response(
            request_cmd=b"\x03\x03",
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info("Device is in connection")
        return True

    def set_baudrate(self, baudrate: int) -> bool:
        """
        Set the baudrate of the fingerprint module.

        Parameters:
            baudrate: The baudrate to set.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        response = self._request_and_response(
            request_cmd=b"\x03\x04",
            request_data=baudrate.to_bytes(4, byteorder="big"),
            response_valid_status=b"\x00\x00\x00\x00",
        )
        if response is None:
            return False

        self.logger.info(f"Set baudrate to {baudrate}")
        return True

    def set_password(self, new_passwd: bytes, write_to_flash: bool = False) -> bool:
        """
        Set the communication password of the fingerprint module.

        Parameters:
            new_passwd: The new password to set.
            write_to_flash:
                Whether to write the new password to flash.
                If writing to flash, the new password will be saved permanently.
                Otherwise, the new password will be lost after power off.

        Returns:
            bool: True if the command was sent successfully, otherwise False.
        """

        if len(new_passwd) != 4:
            raise ValueError("Password must be 4 bytes long")

        cmd = b"\x02\x01" if not write_to_flash else b"\x03\x05"
        request = self._request(cmd=cmd, data=new_passwd)
        if request is None:
            return False

        packet_size = ResponsePacket.packet_size(data_size=0)
        packet_bytes = self.comm.read(size=packet_size)
        response = ResponsePacket.from_bytes(packet_bytes, new_passwd)

        if response.cmd != request.cmd:
            self.logger.error("Command mismatch in response packet", exc_info=True)
            return False
        if response.status != b"\x00\x00\x00\x00":
            self.logger.error(f"Failed to set new password: {response.status}")
            return False

        self.passwd = new_passwd
        self.logger.info(
            f"Set new password (write_to_flash={write_to_flash}): {new_passwd}"
        )
        return True

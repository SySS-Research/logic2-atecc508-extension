from distutils.command.build_scripts import first_line_re
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting
import struct
import hashlib
import re


class ATECC508A(HighLevelAnalyzer):
    
    readKeyHex = StringSetting(label="I2C Read Key 32 Bytes (Hex string)")
    writeKeyHex = StringSetting(label="I2C Write Key 32 Bytes (Hex string)")

    # Define dummy readKey
    readKey = bytearray(
        [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1A,
            0x1B,
            0x1C,
            0x1D,
            0x1E,
            0x1F,
        ]
    )

    # Define dummy writeKey
    writeKey = bytearray(
        [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1A,
            0x1B,
            0x1C,
            0x1D,
            0x1E,
            0x1F,
        ]
    )

    commands = {
        0x28: "CheckMac",
        0x24: "Counter",
        0x1C: "DeriveKey",
        0x43: "ECDH",
        0x15: "GenDig",
        0x40: "GenKey",
        0x11: "HMAC",
        0x30: "Info",
        0x17: "Lock",
        0x8: "MAC",
        0x16: "Nonce",
        0x1: "Pause",
        0x46: "PrivWrite",
        0x2: "Read",
        0x41: "Sign",
        0x47: "SHA",
        0x20: "UpdateExtra",
        0x45: "Verify",
        0x12: "Write",
    }

    # Variables for Encrypted Read/Write
    lastCommandNonce = False
    lastCommandEncryptedRead = False
    lastCommandRead = False
    lastCommandGenDig = False
    lastRandOut = bytearray([])
    lastNumIn = bytearray([])

    def generateNonce(self, randOut, numIn, mode=0):
        # Generate Nonce as described in the "Nonce Command" chapter in the datasheet
        n = hashlib.sha256()

        nonceHashInput = bytearray([])
        nonceHashInput.extend(randOut)  # Random Number Nonce Command
        nonceHashInput.extend(numIn)  # Input for Nonce Command
        nonceHashInput.append(0x16)  # Opcode Nonce Command
        nonceHashInput.append(mode)  # Mode Nonce Command
        nonceHashInput.append(0x00)  # Extra Zero

        n.update(nonceHashInput)
        nonce = n.digest()
        return nonce

    def generateSessionKey(self, keyId, key, nonce):
        # Generate SessionKey as described in the "GenDig Command" chapter in the datasheet
        sessionKeyInput = bytearray([])

        sessionKeyInput.extend(key)
        sessionKeyInput.append(0x15)  # Opkey GenDig
        sessionKeyInput.append(0x02)  # Zone 0x02
        sessionKeyInput.append(keyId)  # KEY ID
        sessionKeyInput.append(0x0)  # NullByte
        # Serialnumber Bytes 0,1 and 8 are fixed for all ATECC508A as described in the datasheet
        sessionKeyInput.append(0xEE)  # SN[8]
        sessionKeyInput.extend(bytearray([0x01, 0x23]))  # SN[0:1]
        sessionKeyInput.extend(bytearray(25))  # 25 Zeroes
        sessionKeyInput.extend(nonce)  # Nonce

        m = hashlib.sha256()
        m.update(sessionKeyInput)
        sessionKey = m.digest()

        return sessionKey

    result_types = {"ATECC508A": {"format": "{{type}}"}}
    temp_frame = AnalyzerFrame("init", None, None)
    temp_frame.data = {}

    def __init__(self):
        """
        Initialize HLA for Microchip ATECC508A.
        """
        if self.writeKeyHex != "":
            self.writeKey = bytearray.fromhex(self.writeKeyHex)

        else:
            print("Dummy I2C write key loaded")

        if self.readKeyHex != "":
            self.readKey = bytearray.fromhex(self.readKeyHex)
        else:
            print("Dummy I2C read key laoaded")

        print(f"WriteKey {self.writeKey.hex()}")
        print(f"ReadKey {self.readKey.hex()}")
        if len(self.readKey) != 32 or len(self.writeKey) != 32:
            print("ERROR: Read and write key must be 32 Bytes long")
            quit()

    def parseAddressZone(self, data):
        first_param = format(int(data[3], 16), "08b")
        if first_param[0] == "1":
            self.temp_frame.data["Size"] = "32 Byte"
        else:
            self.temp_frame.data["Size"] = "8 Byte"

        if first_param[-2:] == "00":
            self.temp_frame.data["Zone"] = "Config"
        if first_param[-2:] == "01":
            self.temp_frame.data["Zone"] = "OTP"
        if first_param[-2:] == "10":
            self.temp_frame.data["Zone"] = "Data"
        if data[2] == "0x12":
            if first_param[1] == "1":
                self.temp_frame.data["Write: Encrypted"] = "True"

        if self.temp_frame.data["Zone"] == "Data":
            print("Zone Data")
            first_byte = format(int(data[4], 16), "08b")
            second_byte = format(int(data[5], 16), "08b")
            slot = int(first_byte[1:5], 2)
            print(f"Slot {slot}")
            self.temp_frame.data["Slot"] = str(slot)
            self.temp_frame.data["Offset"] = str(int(first_byte[-3:], 2))
            try:
                if slot < 8:
                    # print("<8")
                    print(f"Block {str(int(second_byte[-1:], 2))}")
                    self.temp_frame.data["Block"] = str(int(second_byte[-1:], 2))
                if slot == 8:
                    # print("=8")
                    print(f"Block {str(int(second_byte[-4:], 2))}")
                    self.temp_frame.data["Block"] = str(int(second_byte[-4:], 2))
                if slot > 8:
                    # print(">8")
                    print(f"Block {str(int(second_byte[-2:], 2))}")
                    self.temp_frame.data["Block"] = str(int(second_byte[-2:], 2))
            except Exception as e:
                print(e)

        else:
            first_byte = format(int(data[4], 16), "08b")
            second_byte = format(int(data[5], 16), "08b")
            self.temp_frame.data["Offset"] = str(int(first_byte[-3:], 2))
            if self.temp_frame.data["Zone"] == "Config":
                print("Zone Config")
                self.temp_frame.data["Block"] = str(int(first_byte[3:5], 2))
                print(f"Block {str(int(first_byte[3:5], 2))}")
            if self.temp_frame.data["Zone"] == "OTP":
                print("Zone OTP")
                self.temp_frame.data["Block"] = str(int(first_byte[4:5]), 2)
                print(f"Block {str(int(first_byte[4:5]), 2)}")

    def ateccAnalyzer(self):
        if self.temp_frame.data["count"] is 0:
            return
        data = self.temp_frame.data["data"].split(",")
        try:
            # Parse I2C Packets sent from master
            if self.temp_frame.data["read"] == False:
                self.temp_frame.data["Word address"] = "Unknown"
                # Case: Reset
                if data[0] == "0x0":
                    self.temp_frame.data["Word address"] = "Reset address counter"
                # Case: Sleep Mode
                if data[0] == "0x1":
                    self.temp_frame.data["Word address"] = "Sleep Mode"
                # Case: Idle
                if data[0] == "0x2":
                    self.temp_frame.data["Word address"] = "Idle Mode"
                # Case: Command
                if data[0] == "0x3":
                    try:
                        print(f"[->] Command: {self.commands[int(data[2], 16)]}")
                        self.temp_frame.data["Word address"] = (
                            "Command: " + self.commands[int(data[2], 16)]
                        )
                    except:
                        print("Command not found")
                    try:
                        if data[2] == "0x2":
                            # Command Read
                            self.parseAddressZone(data)
                            if self.lastCommandGenDig == True:
                                self.lastCommandEncryptedRead = True
                                self.lastCommandGenDig = False
                            else:
                                self.lastCommandRead = True
                        if data[2] == "0x12":
                            # Command Write
                            self.parseAddressZone(data)
                            if self.temp_frame.data["Write: Encrypted"] == "True":
                                self.lastCommandGenDig = False
                                cipherText = bytearray([int(i, 16) for i in data])[6:38]
                                clearText = self.decryptWrite(
                                    self.lastRandOut, cipherText, self.writeKey
                                )

                                self.temp_frame.data["Cleartext"] = ",".join(
                                    hex(b) for b in clearText
                                )
                        if data[2] == "0x15":
                            # Command GenDig
                            self.lastCommandGenDig = True
                        if data[2] == "0x16":
                            # Command Nonce
                            # If Nonce in Random Mode, set Flag to capture Response
                            if data[3] == "0x0":
                                self.lastCommandNonce = True
                                dataBytes = bytearray([int(i, 16) for i in data])
                                self.lastNumIn = dataBytes[6:26]
                            # Pass-trough mode
                            if data[3] == "0x3":
                                print(f"Pass through mode, set nonce:")
                                dataBytes = bytearray([int(i, 16) for i in data])
                                self.printHexDebug(dataBytes[6:-2])

                        if data[2] == "0x24":
                            # Command Counter
                            if data[3] == "0x0":
                                print(f"Read Counter {int(data[5],16)}")
                            else:
                                print(f"Increment Counter {int(data[5],16)}")

                    except Exception as e:
                        print(e)

                    self.temp_frame.data["First Parameter"] = format(
                        int(data[3], 16), "08b"
                    )
                    self.temp_frame.data["Second Parameter"] = (
                        format(int(data[5], 16), "08b")
                        + " "
                        + format(int(data[4], 16), "08b")
                    )

            # Parse I2C Responses from ATECC508A
            if self.temp_frame.data["read"] == True:
                # Only parse resonses with data
                if len(data) > 1:
                    # Capture RandOut if Flag is set to true
                    if self.lastCommandNonce == True:
                        nonceResponse = bytearray([int(i, 16) for i in data])
                        self.lastRandOut = nonceResponse[:-2]
                        print("[<-] Result of nonce command")
                        self.printHexDebug(self.lastRandOut)
                        self.lastCommandNonce = False
                    elif self.lastCommandRead == True:
                        self.lastCommandRead = False
                        readResult = bytearray([int(i, 16) for i in data])[:-2]
                        print("[<-] Result of read command")
                        self.printHexDebug(readResult)
                    elif self.lastCommandEncryptedRead == True:
                        cipherText = bytearray([int(i, 16) for i in data])[:-2]

                        clearText = self.decryptRead(self.lastRandOut, cipherText)

                        print("[<-] Cleartext of encrypted read command")
                        self.printHexDebug(clearText)

                        self.temp_frame.data["Cleartext"] = ",".join(
                            hex(b) for b in clearText
                        )

                        self.lastCommandEncryptedRead = False
                    else:
                        # Print return Values of other commands, if not 00

                        readResult = bytearray([int(i, 16) for i in data])[:-2]
                        if readResult != bytearray([0x00]):
                            print("[<-] Command result")
                            self.printHexDebug(readResult)

        except Exception as e:
            print(e)
            # print("Parsing failed")

    def decode(self, frame: AnalyzerFrame):
        """
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        """

        if self.temp_frame.type is "init":
            self.temp_frame.type = "error"
            self.temp_frame.start_time = frame.start_time
            self.temp_frame.end_time = frame.end_time
            self.temp_frame.data["address"] = "error"
            self.temp_frame.data["data"] = ""
            self.temp_frame.data["count"] = 0
            self.temp_frame.data["Word address"] = ""
            self.temp_frame.data["Cleartext"] = ""

        if frame.type == "start" or (
            frame.type == "address" and self.temp_frame.type == "error"
        ):
            self.temp_frame.type = "ATECC508A"
            self.temp_frame.start_time = frame.start_time

        if frame.type == "address":
            address_byte = frame.data["address"][0]
            self.temp_frame.data["address"] = hex(address_byte)
            self.temp_frame.data["read"] = frame.data["read"]

        if frame.type == "data":
            data_byte = frame.data["data"][0]
            self.temp_frame.data["count"] += 1
            if len(self.temp_frame.data["data"]) > 0:
                self.temp_frame.data["data"] += ","
            self.temp_frame.data["data"] += hex(data_byte)

        if frame.type == "stop":
            self.temp_frame.end_time = frame.end_time

            if self.temp_frame.data["address"] == hex(0x60):
                self.ateccAnalyzer()

            return_frame = AnalyzerFrame(
                self.temp_frame.type,
                self.temp_frame.start_time,
                self.temp_frame.end_time,
                self.temp_frame.data,
            )
            self.temp_frame.data = {}
            self.temp_frame.type = "init"
            return return_frame

    def decryptWrite(
        self, randOut: bytearray, cipherText: bytearray, writeKey: bytearray
    ):
        # Generate Nonce
        nonce = self.generateNonce(randOut, self.lastNumIn)

        # print("Nonce:")
        # self.printHexDebug(nonce)

        # Generate Session Key
        sessionKey = self.generateSessionKey(0x03, self.writeKey, nonce)

        # print("SessionKey:")
        # self.printHexDebug(sessionKey)

        # Decrypt
        clearText = bytearray([])
        j = 0
        for j in range(0, 32):
            clearText.append(cipherText[j] ^ sessionKey[j])
        print(f"Cleartext of encrypted write command")
        self.printHexDebug(clearText)
        return clearText

    def decryptRead(self, randOut: bytearray, cipherText: bytearray):
        # Generate Nonce
        nonce = self.generateNonce(randOut, self.lastNumIn)

        # print("Nonce:")
        # self.printHexDebug(nonce)

        # Generate Session Key
        sessionKey = self.generateSessionKey(0x04, self.readKey, nonce)

        # print("SessionKey:")
        # self.printHexDebug(sessionKey)

        # Decrypt
        clearText = bytearray([])
        j = 0
        for j in range(0, 32):
            clearText.append(sessionKey[j] ^ cipherText[j])

        # print("Ciphertext:")
        # self.printHexDebug(cipherText)

        # print("Decrypted Ciphertext:")
        # self.printHexDebug(clearText)
        return clearText

    def printHexDebug(self, ba):
        i = 0

        for b in ba:
            print(f"{b:02x}", end=" ")
            i = i + 1
            if i % 8 == 0:
                if i % 16 == 0:
                    print()
                else:
                    print("", end=" ")
        print()

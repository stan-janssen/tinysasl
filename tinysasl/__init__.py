# Copyright 2020 Stan Janssen

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import secrets
import hmac
import hashlib
import re
import stringprep
from base64 import b64encode, b64decode


class SASL:
    def __init__(self, username, password, mechanism="PLAIN", base64=False, hash_name='sha256'):
        self.username = username.encode()
        self.password = sasl_prep(password).encode()
        self.mechanism = mechanism
        self.base64 = base64
        self.hash_name = hash_name
        self.nonce = b64encode(secrets.token_bytes(32))

    def initial_message(self, include_gs2_header=True, base64=False):
        message = b'n=' + self.username + b',r=' + self.nonce
        if include_gs2_header:
            message = b'n,,' + message
        if base64 is None:
            base64 = self.base64
        if base64:
            message = b64encode(message)
        return message

    def response(self, challenge):
        """
        Calculate the response to the given challenge.
        """
        if isinstance(challenge, str):
            challenge = challenge.encode()
        if self.base64:
            challenge = b64decode(challenge)
        server_nonce, salt, iterations = re.match(rb"r=(.*?),s=(.*),i=(.*)", challenge).groups()
        salt = b64decode(salt)
        iterations = int(iterations)
        client_final_message_bare = b"c=biws,r=" + server_nonce
        salted_password = hashlib.pbkdf2_hmac(hash_name=self.hash_name, password=self.password,
                                              salt=salt, iterations=iterations)
        client_key = hmac.digest(key=salted_password, msg=b"Client Key", digest=self.hash_name)
        stored_key = hashlib.new(name=self.hash_name, data=client_key).digest()
        initial_message = self.initial_message(include_gs2_header=False, base64=False)
        auth_message = initial_message + b',' + challenge + b',' + client_final_message_bare

        client_signature = hmac.digest(key=stored_key,
                                       msg=auth_message,
                                       digest=self.hash_name)


        client_proof_value = bytes(a ^ b for a, b in zip(client_key, client_signature))
        client_proof = b64encode(client_proof_value)

        self.server_key = hmac.digest(key=salted_password,
                                      msg=b"Server Key",
                                      digest=self.hash_name)
        self.server_signature = hmac.digest(key=self.server_key,
                                            msg=auth_message,
                                            digest=self.hash_name)
        client_final_message = client_final_message_bare + b',p=' + client_proof
        if self.base64:
            client_final_message = b64encode(client_final_message)
        return client_final_message

    def verify_server_final_message(self, server_final_message):
        """
        Validate the given (b64-encoded) server signature against what we expect it to be.
        """
        if isinstance(server_final_message, str):
            server_final_message = server_final_message.encode()
        if self.base64:
            server_final_message = b64decode(server_final_message)
        b64encoded_v, = re.match(rb'v=(.*)', server_final_message).groups()
        v = b64decode(b64encoded_v)
        if v != self.server_signature:
            raise ValueError("Invalid Server Signature value")
        return True


def sasl_prep(text):
    """
    Performs a SASL-PREP on the string to ensure it is SASL-compatible.
    """
    normalized_chars = []
    for c in text:
        if stringprep.in_table_c12(c):
            continue
        if stringprep.in_table_c21(c):
            continue
        if stringprep.in_table_c22(c):
            continue
        if stringprep.in_table_c3(c):
            continue
        if stringprep.in_table_c4(c):
            continue
        if stringprep.in_table_c5(c):
            continue
        if stringprep.in_table_c6(c):
            continue
        if stringprep.in_table_c7(c):
            continue
        if stringprep.in_table_c8(c):
            continue
        if stringprep.in_table_c9(c):
            continue
        normalized_chars.append(c)

    return "".join(normalized_chars)

# TinySASL

Small Python package to generate SASL messages.

## Installation

```
pip install --user tinysasl
```

## Usage

```python
from tinysasl import SASL

# Create a SASL object that can generate the messages
sasl = SASL('username', 'password')

# Create the initial message to send
initial_message = sasl.initial_message()

# After receiving the challenge, calculate the response:
response_message = sasl.response_message(challenge)

# After receiving the reply to the challenge-response, verify the final message
try:
    sasl.verify_server_final_message(final_message)
except ValueError:
    print("Verification failed!")
```

### Base64 mode or bytes-mode

By default, the SASL object expects and returns `bytes`. If your protocol requires sending the SASL messages as base64-encoded strings, you can enable that when initializing:

```python
sasl = SASL('username', 'password', base64=True)
```

### Using a different hash method

By default, the SASL object will use the `sha256` digest method. If you need a different method, you can pass a string into the initialization that is supported by Python's `hashlib` on your system. You can get a list of supported methods from `hashlib.algorithms_available`. For example, to use the blake2b algo:

```python
sasl = SASL('username', 'password', hash_name='blake2b')
```

## License

TinySASL is made available under the Apache 2.0 license.

## Development

You can follow the development of TinySASL on [GitHub](https://github.com/stan-janssen/tinysasl).

## Contributing

To contribute to TinySASL, please open an issue on our [GitHub issue tracker](https://github.com/stan-janssen/tinysasl/issues) and/or leave a Pull Request. Thanks!

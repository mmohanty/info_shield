import pytest
import base64, json
from info_shield.validators.jwt_validator import JwtValidator

def make_jwt(payload):
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signature = "dummy"
    return f"{header}.{body}.{signature}"

@pytest.mark.parametrize("jwt,expected", [
    (make_jwt({"sub":"1234567890","name":"John Doe"}), True),
    ("invalid.jwt.token", False),
])
def test_jwt_validator(jwt, expected):
    v = JwtValidator()
    res = v.validate(jwt)
    assert res.ok == expected

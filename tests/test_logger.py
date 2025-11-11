from core.secure_logger import encrypt_data

def test_encrypt():
    data = "test:user:pass"
    encrypted = encrypt_data(data)
    assert isinstance(encrypted, str)
    assert len(encrypted) > 10
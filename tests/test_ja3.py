from tlsight import ja3
from tlsight.ciphers import is_grease


def test_ja3_reference_vector():
    # Example from the salesforce/ja3 README
    s = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    assert ja3.md5(s) == "ada70206e40642a3e4461f35503241d5"


def test_ja3s_string_layout():
    # SSLVersion,Cipher,SSLExtension (the README publishes no raw JA3S string to test against)
    s = ja3.ja3s_string(769, 47, [65281, 0, 11, 35, 5, 16])
    assert s == "769,47,65281-0-11-35-5-16"
    assert ja3.ja3s_string(771, 4865, [0x2A2A, 43, 51]) == "771,4865,43-51"


def test_ja3_string_layout():
    s = ja3.ja3_string(769, [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
                       [0, 10, 11], [23, 24, 25], [0])
    assert s == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"


def test_grease_is_removed():
    s = ja3.ja3_string(771, [0x0A0A, 4865, 4866], [0x1A1A, 0, 43, 0xFAFA], [0x2A2A, 29], [0])
    assert s == "771,4865-4866,0-43,29,0"


def test_grease_detection():
    assert all(is_grease(0x0A0A + 0x1010 * i) for i in range(16))
    assert not is_grease(0x1301)
    assert not is_grease(0x0A0B)


def test_empty_fields():
    assert ja3.ja3_string(771, [4865], [], [], []) == "771,4865,,,"

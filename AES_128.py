from utils import expand_key, sub_word, shift_rows_1d, mix_columns, XOR, inv_mix_columns, inv_sub_word, inv_shift_rows_1d

def encode_aes_128(block_plain_text, session_key):
    lst_round_key = expand_key(session_key)  # Sinh round keys 
    # XOR với round key đầu tiên
    state = XOR(block_plain_text, lst_round_key[0])

    for i in range(1, 10):
        state = sub_word(state)
        state = shift_rows_1d(state)
        state = mix_columns(state)
        state = XOR(state, lst_round_key[i])

    state = sub_word(state)
    state = shift_rows_1d(state)
    state = XOR(state, lst_round_key[10])

    return bytes(state)  # ✅ Trả về dạng bytes thay vì chuỗi ASCII


def decode_aes_128(ciphertext, session_key):
    lst_round_key = expand_key(session_key)  # Sinh round keys
    state = bytearray(ciphertext)

    # XOR với round key cuối cùng
    state = XOR(state, lst_round_key[10])
    state = inv_shift_rows_1d(state)
    state = inv_sub_word(state)

    for i in range(9, 0, -1):
        state = XOR(state, lst_round_key[i])
        state = inv_mix_columns(state)
        state = inv_shift_rows_1d(state)
        state = inv_sub_word(state)

    # XOR với round key đầu tiên
    state = XOR(state, lst_round_key[0])

    return bytes(state).decode("ascii")  # ✅ Giữ nguyên bytes trước khi decode

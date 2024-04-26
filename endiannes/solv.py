word = "" ## ISI DENGAN KARAKTER YANG DIPERINTAHKAN

# Konversi kata ke dalam bentuk byte array (UTF-8 encoded)
byte_array = word.encode('utf-8')

# Representasi little endian
little_endian_byte_array = byte_array[::-1]## HAPUS BILA INGIN MENJADIKANNYA BIG ENDIANN

# Representasi dalam bentuk hex byte
little_endian_hex_representation = ''.join(format(byte, '02X') for byte in little_endian_byte_array)

print("Little Endian representation:", little_endian_hex_representation)


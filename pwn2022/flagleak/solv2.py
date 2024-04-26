hex_string = "6f6369707b4654436b34334c5f676e3167346c466666305f3474535f395f6b63326539397d343238fbad20008d14e000"

# Menghapus titik dari string heksadesimal
hex_string = hex_string.replace(".", "")

# Mengonversi string heksadesimal menjadi byte array
byte_array = bytes.fromhex(hex_string)

# Mengonversi byte array menjadi little endian
little_endian = byte_array[::-1]

# Mengonversi little endian menjadi string menggunakan ASCII atau UTF-8
text = little_endian.decode("ascii")  # Ubah ke ASCII jika data hanya berisi karakter ASCII
# text = little_endian.decode("utf-8")  # Ubah ke UTF-8 jika data berisi karakter internasional

print("String:", text)

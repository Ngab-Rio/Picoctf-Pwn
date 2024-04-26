def main():
    v22 = "picoCTF{wELF_d0N3_mate_"
    v23 = "9"
    v24 = "5"
    v25 = "a"
    v26 = "3"
    v27 = "c"
    v28 = "9"
    v29 = "a"
    v30 = "e"
    v31 = "5"
    v32 = "d"
    v33 = "b"
    v34 = "9"
    v35 = "6"
    v36 = "b"
    v37 = "3"
    v38 = "8"

    if ord(v24[0]) <= 65:
        v22 += v34
    if ord(v35[0]) != 65:
        v22 += v37
    # Note: The condition "Hello" == "World" is always False, so it does nothing in C++ code.
    # It's removed here.

    # Conversion of subtraction
    v19 = ord(v26[0])
    if v19 - ord(v30[0]) == 3:
        v22 += v26

    v22 += v25
    v22 += v28
    if ord(v29[0]) == 71:
        v22 += v29
    v22 += v27
    v22 += v36
    v22 += v23
    v22 += v31
    v22 += "}"
    
    print(v22)

if __name__ == "__main__":
    main()

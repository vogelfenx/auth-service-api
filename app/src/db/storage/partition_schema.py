USER_PARTITION_SCHEMA = {
    0: {  # ASCII
        "part_from": 0,
        "part_to": 255
    },
    1: {  # from ASCII to Cyrillic
        "part_from": 255,
        "part_to": 1040
    },
    2: {  # Cyrillic
        "part_from": 1040,
        "part_to": 1103
    },
    3: {  # Others
        "part_from": 1103,
        "part_to": 1114111  # sys.maxunicode
    }
}

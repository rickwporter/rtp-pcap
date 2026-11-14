#include "hexutils.h"
#include "test_harness.h"

static void test_ascii2nibble() {
    EXPECT(ascii2nibble('0') == 0);
    EXPECT(ascii2nibble('9') == 9);
    EXPECT(ascii2nibble('A') == 10);
    EXPECT(ascii2nibble('F') == 15);
    EXPECT(ascii2nibble('a') == 10);
    EXPECT(ascii2nibble('f') == 15);
    EXPECT(ascii2nibble('G') == 0);
    EXPECT(ascii2nibble(' ') == 0);
}

static void test_hexString2Binary() {
    uint8_t binary[8];
    EXPECT(hexString2Binary(binary, "0x0A0b") == 2);
    EXPECT(binary[0] == 0x0a);
    EXPECT(binary[1] == 0x0b);
    EXPECT(hexString2Binary(binary, "0a 0b") == 2);
    EXPECT(binary[0] == 0x0a);
    EXPECT(binary[1] == 0x0b);
    EXPECT(hexString2Binary(binary, "0x") == 0);
    EXPECT(hexString2Binary(binary, "") == 0);
    EXPECT(hexString2Binary(binary, "zz") == -1);
    EXPECT(hexString2Binary(binary, "abc") == -1);
    EXPECT(hexString2Binary(binary, "AG") == -1);
}

static void test_bin2hexString_r() {
    uint8_t bytes[] = {0x0a, 0xff};
    char text[8];
    EXPECT_STREQ(bin2hexString_r(text, bytes, 2), "0aff");
    EXPECT_STREQ(bin2hexString_r(text, bytes, 0), "");
}

static void test_bin2hexString() {
    uint8_t bytes[] = {0x0a, 0xff};
    EXPECT_STREQ(bin2hexString(bytes, 2), "0aff");
}

static void test_hexdump() {
    uint8_t row[16];
    for (int i = 0; i < 16; i++) {
        row[i] = static_cast<uint8_t>(i);
    }
    const char *full = hexdump(row, 16);
    EXPECT_STREQ(full, "00000000: 00010203 04050607 08090A0B 0C0D0E0F   ................\n");
}

static void test_hexdump_r() {
    uint8_t row[16];
    for (int i = 0; i < 16; i++) {
        row[i] = static_cast<uint8_t>(i);
    }

    char small[8];
    const char *too_small = NULL;
    std::string small_message = capture([&]() { too_small = hexdump_r(row, 16, small, sizeof(small)); });
    EXPECT(too_small == NULL);
    EXPECT_CONTAINS(small_message, "must have at least 80-byte output buffer");
    EXPECT(hexdump_r(NULL, 16, small, sizeof(small)) == NULL);
    EXPECT(hexdump_r(row, 16, NULL, sizeof(small)) == NULL);

    char empty[8];
    EXPECT_STREQ(hexdump_r(row, 0, empty, sizeof(empty)), "");

    uint8_t letter = 'A';
    char one[96];
    std::string expected = "00000000: 41";
    expected.append(36, ' ');
    expected += "A\n";
    EXPECT_STREQ(hexdump_r(&letter, 1, one, sizeof(one)), expected.c_str());

    uint8_t seventeen[17];
    memset(seventeen, 0x41, sizeof(seventeen));
    char multi[256];
    const char *dumped = hexdump_r(seventeen, 17, multi, sizeof(multi));
    EXPECT(dumped == multi);
    EXPECT(strstr(dumped, "00000000: ") == dumped);
    EXPECT(strstr(dumped, "00000010: ") != NULL);
}

void test_hexutils() {
    test_ascii2nibble();
    test_hexString2Binary();
    test_bin2hexString_r();
    test_bin2hexString();
    test_hexdump();
    test_hexdump_r();
}

#include <cstddef>

#include "base64.h"
#include "test_harness.h"

static void test_base64_encode() {
    size_t out_len = 99;
    unsigned char *empty = base64_encode(reinterpret_cast<const unsigned char *>(""), 0, &out_len);
    EXPECT(empty != NULL);
    EXPECT(out_len == 0);
    EXPECT(empty[0] == '\0');
    free(empty);

    unsigned char ignored = 0;
    unsigned char *no_length = base64_encode(&ignored, 0, NULL);
    EXPECT(no_length != NULL);
    free(no_length);
    EXPECT(base64_encode(&ignored, static_cast<size_t>(-1), NULL) == NULL);

    const char *texts[] = {"f", "fo", "foo", "foob", "fooba", "foobar"};
    const char *encoded_text[] = {"Zg==\n", "Zm8=\n", "Zm9v\n", "Zm9vYg==\n", "Zm9vYmE=\n", "Zm9vYmFy\n"};
    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++) {
        unsigned char *encoded = base64_encode(reinterpret_cast<const unsigned char *>(texts[i]), strlen(texts[i]), &out_len);
        EXPECT(encoded != NULL);
        EXPECT(out_len == strlen(encoded_text[i]));
        EXPECT(strcmp(reinterpret_cast<char *>(encoded), encoded_text[i]) == 0);
        free(encoded);
    }

    std::vector<unsigned char> wrapped(54, 0x41);
    unsigned char *encoded = base64_encode(&(wrapped[0]), wrapped.size(), &out_len);
    EXPECT(encoded != NULL);
    EXPECT(out_len == 73);
    EXPECT(encoded[72] == '\n');
    free(encoded);

    wrapped.push_back(0x42);
    encoded = base64_encode(&(wrapped[0]), wrapped.size(), &out_len);
    EXPECT(out_len == 78);
    EXPECT(encoded[72] == '\n');
    EXPECT(encoded[out_len - 1] == '\n');
    free(encoded);
}

static void expect_base64_decode(const char *encoded, const char *text) {
    size_t decoded_len = 0;
    unsigned char *decoded = base64_decode(reinterpret_cast<const unsigned char *>(encoded), strlen(encoded), &decoded_len);
    EXPECT(decoded != NULL);
    if (decoded != NULL) {
        EXPECT(decoded_len == strlen(text));
        EXPECT(memcmp(decoded, text, strlen(text)) == 0);
        free(decoded);
    }
}

static void test_base64_decode() {
    expect_base64_decode("Zg==\n", "f");
    expect_base64_decode("Zm8=\n", "fo");
    expect_base64_decode("Zm9v\n", "foo");
    expect_base64_decode("Zm9vYg==\n", "foob");
    expect_base64_decode("Zm9vYmE=\n", "fooba");
    expect_base64_decode("Zm9vYmFy\n", "foobar");

    size_t out_len = 0;
    std::vector<unsigned char> wrapped(54, 0x41);
    unsigned char *encoded = base64_encode(&(wrapped[0]), wrapped.size(), &out_len);
    size_t decoded_len = 0;
    unsigned char *decoded = base64_decode(encoded, out_len, &decoded_len);
    EXPECT(decoded_len == wrapped.size());
    EXPECT(memcmp(decoded, &(wrapped[0]), wrapped.size()) == 0);
    free(decoded);
    free(encoded);

    wrapped.push_back(0x42);
    encoded = base64_encode(&(wrapped[0]), wrapped.size(), &out_len);
    decoded = base64_decode(encoded, out_len, &decoded_len);
    EXPECT(decoded_len == wrapped.size());
    EXPECT(memcmp(decoded, &(wrapped[0]), wrapped.size()) == 0);
    free(decoded);
    free(encoded);

    expect_base64_decode("Zm9v\nYmFy", "foobar");

    EXPECT(base64_decode(reinterpret_cast<const unsigned char *>(""), 0, &decoded_len) == NULL);
    EXPECT(base64_decode(reinterpret_cast<const unsigned char *>("\n\n"), 2, &decoded_len) == NULL);
    EXPECT(base64_decode(reinterpret_cast<const unsigned char *>("YQ="), 3, &decoded_len) == NULL);
    EXPECT(base64_decode(reinterpret_cast<const unsigned char *>("!!!!"), 4, &decoded_len) == NULL);
    EXPECT(base64_decode(reinterpret_cast<const unsigned char *>("Y==="), 4, &decoded_len) == NULL);
    EXPECT(base64_decode(reinterpret_cast<const unsigned char *>("===="), 4, &decoded_len) == NULL);

    decoded = base64_decode(reinterpret_cast<const unsigned char *>("YQ=="), 4, &decoded_len);
    EXPECT(decoded_len == 1);
    EXPECT(decoded[0] == 'a');
    free(decoded);
}

void test_base64() {
    test_base64_encode();
    test_base64_decode();
}

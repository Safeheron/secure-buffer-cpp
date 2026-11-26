// Consumers often build with -Wconversion -Wsign-conversion -Werror. Non-template
// code in the public headers is checked by including them; templates only warn
// when instantiated, so every public template is instantiated here.
#include <secure-buffer/secure_buffer.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>

namespace {
struct Keys {
    std::array<std::uint8_t, 16> a;
};
} // namespace

template <>
struct safeheron::secure_buffer::enable_secure_cleanse<Keys> : std::true_type {};

int main() {
    using namespace safeheron::secure_buffer;

    SecureArray<std::uint32_t, 8> words;
    words[1] = 2;
    std::uint32_t sum = words.at(3) + words.front() + words.back();
    for (std::uint32_t& w : words) w = sum;
    SecureArray<std::byte, 4> bytes;
    SecureArray<std::byte, 4> copy = bytes;
    copy = bytes;
    SecureArray<std::uint8_t, 0> empty;
    secure_cleanse(empty);
    secure_cleanse(copy);
    bool same = constant_time_equal(words, words);

    std::uint8_t raw[16] = {};
    secure_cleanse(raw);
    { ScopedCleanse guard(raw); }
    Keys keys{};
    { ScopedCleanse guard(keys); }
    std::array<Keys, 2> key_array{};
    secure_cleanse(key_array);

    SecureBytes sb = make_secure_bytes<32>();
    same = constant_time_equal(sb, sb) && same;
    std::string plain = "abc";
    SecureBytes from_plain = to_secure_bytes(plain);
    SecureString str = to_secure_string(plain);
    str.resize(8, 'x');
    str.append(4, 'y');
    same = constant_time_equal(str, str) && same;
    same = to_unsecure_string(from_plain) == plain && same;

    SecureAllocator<std::uint32_t> alloc;
    std::uint32_t* p = alloc.allocate(4);
    alloc.deallocate(p, 4);

    return same ? 0 : 1;
}

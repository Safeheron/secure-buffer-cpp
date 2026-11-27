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

    std::size_t n = 2;
    compat::span<std::uint8_t> raw_view(raw, sizeof(raw));
    compat::span<const std::uint32_t, 8> word_view(words.data(), words.size());
    same = raw_view.first(n).size() + raw_view.last(n).size() == 2 * n && same;
    same = raw_view.subspan(n, n)[0] == raw[n] && raw_view.subspan(n).size_bytes() == 14 && same;
    same = word_view.subspan(n, n)[0] == words[n] && word_view.first(n).size_bytes() == 8 && same;
    same = word_view.last(n)[n - 1] == words[7] && word_view.size_bytes() == 32 && same;
    same = raw_view.first<2>().size() + raw_view.last<2>().size() == 4 && same;
    same = raw_view.subspan<2>().size() == 14 && raw_view.subspan<2, 3>()[0] == raw[2] && same;
    same = word_view.first<2>()[1] == words[1] && word_view.last<2>()[1] == words[7] && same;
    same = word_view.subspan<2>().size_bytes() == 24 && word_view.subspan<2, 3>()[2] == words[4] &&
           same;
    compat::span<const std::uint8_t, 16> fixed_view = raw;
    compat::span<const std::uint8_t> dynamic_view = fixed_view;
    compat::span<const std::uint8_t, 16> back_view(dynamic_view);
    compat::span<const Keys, 2> key_view = key_array;
    compat::span<const std::uint8_t> empty_view;
    const std::array<std::uint32_t, 8> const_words{};
    compat::span<const std::uint32_t, 8> const_word_view(const_words);
    same = empty_view.begin() == empty_view.end() && empty_view.empty() && same;
    same = static_cast<std::size_t>(const_word_view.end() - const_word_view.begin()) == 8 && same;
    same = back_view.data() == raw && key_view.size() == 2 && same;
    std::ptrdiff_t step = 2;
    auto it = raw_view.begin() + step;
    auto word_it = step + word_view.begin();
    it += step;
    word_it -= step;
    same = it[step] == raw[6] && *(it - step) == raw[2] && (raw_view.end() - it) == 12 &&
           word_it[step] == words[2] && word_view.end() - word_it == 8 && same;

    same = as_span(words).first<2>().size() == 2 && as_writable_span(words).last<2>().size() == 2 &&
           as_span(empty).subspan<0>().empty() && same;

    SecureArray<std::uint8_t, 16> ct_a;
    SecureArray<std::uint8_t, 16> ct_b;
    compat::span<const std::uint8_t> ct_lhs = as_span(ct_a);
    compat::span<const std::uint8_t> ct_rhs = as_span(ct_b);
    same = constant_time_equal(ct_lhs, ct_rhs) && same;

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

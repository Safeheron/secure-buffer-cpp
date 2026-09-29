#include <gtest/gtest.h>
#include <secure-buffer/secure_utils.h>
#include <string>

using namespace safeheron::secure_buffer;

// --- to_secure_bytes(const std::string&) ---

TEST(ToSecureBytesTest, Empty) {
    std::string input;
    SecureBytes result = to_secure_bytes(input);
    EXPECT_TRUE(result.empty());
}

TEST(ToSecureBytesTest, Ascii) {
    std::string input = "hello";
    SecureBytes result = to_secure_bytes(input);
    EXPECT_EQ(result.size(), 5u);
    EXPECT_EQ(result[0], 'h');
    EXPECT_EQ(result[4], 'o');
}

TEST(ToSecureBytesTest, BinaryWithNull) {
    std::string input("a\0b\0c", 5);
    SecureBytes result = to_secure_bytes(input);
    EXPECT_EQ(result.size(), 5u);
    EXPECT_EQ(result[0], 'a');
    EXPECT_EQ(result[1], 0);
    EXPECT_EQ(result[2], 'b');
    EXPECT_EQ(result[3], 0);
    EXPECT_EQ(result[4], 'c');
}

// --- to_unsecure_string(const SecureBytes&) ---

TEST(ToUnsecureStringTest, EmptyBytes) {
    SecureBytes empty;
    std::string result = to_unsecure_string(empty);
    EXPECT_TRUE(result.empty());
}

TEST(ToUnsecureStringTest, Ascii) {
    SecureBytes bytes = {'h', 'e', 'l', 'l', 'o'};
    std::string result = to_unsecure_string(bytes);
    EXPECT_EQ(result, "hello");
}

TEST(ToUnsecureStringTest, BinaryWithNull) {
    SecureBytes bytes = {'a', 0, 'b', 0, 'c'};
    std::string result = to_unsecure_string(bytes);
    EXPECT_EQ(result.size(), 5u);
    EXPECT_EQ(result[0], 'a');
    EXPECT_EQ(result[1], 0);
    EXPECT_EQ(result[2], 'b');
    EXPECT_EQ(result[3], 0);
    EXPECT_EQ(result[4], 'c');
}

// --- to_secure_string(const std::string&) ---

TEST(ToSecureStringTest, Empty) {
    std::string input;
    SecureString result = to_secure_string(input);
    EXPECT_TRUE(result.empty());
}

TEST(ToSecureStringTest, Ascii) {
    std::string input = "mnemonic phrase";
    SecureString result = to_secure_string(input);
    EXPECT_STREQ(result.c_str(), "mnemonic phrase");
    EXPECT_EQ(result.size(), 15u);
}

TEST(ToSecureStringTest, BinaryWithNull) {
    std::string input("x\0y", 3);
    SecureString result = to_secure_string(input);
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0], 'x');
    EXPECT_EQ(result[1], 0);
    EXPECT_EQ(result[2], 'y');
}

// --- Round trip: std::string to SecureBytes and back ---

TEST(ConvertRoundTripTest, BytesRoundTripAscii) {
    std::string original = "secret data";
    SecureBytes bytes = to_secure_bytes(original);
    std::string back = to_unsecure_string(bytes);
    EXPECT_EQ(back, original);
}

TEST(ConvertRoundTripTest, BytesRoundTripBinary) {
    std::string original("\x00\x01\x02\xFF", 4);
    SecureBytes bytes = to_secure_bytes(original);
    std::string back = to_unsecure_string(bytes);
    EXPECT_EQ(back, original);
}

// --- Contract: conversion does not zero the source std::string ---

TEST(ConvertContractTest, ToSecureBytesDoesNotZeroSource) {
    std::string source = "sensitive";
    to_secure_bytes(source);
    EXPECT_EQ(source, "sensitive");
}

TEST(ConvertContractTest, ToSecureStringDoesNotZeroSource) {
    std::string source = "sensitive";
    to_secure_string(source);
    EXPECT_EQ(source, "sensitive");
}

#include "gtest/gtest.h"
#include "netflow++/config_manager.hpp"
#include "netflow++/logger.hpp" // For SwitchLogger

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio> // For std::remove
#include <optional>

// --- Mock/Dummy Implementations ---
class DummySwitchLogger : public netflow::SwitchLogger {
public:
    DummySwitchLogger() : netflow::SwitchLogger(netflow::LogLevel::DEBUG) {}

    void log(netflow::LogLevel level, const std::string& component, const std::string& message) const {
        // No-op for most tests to keep output clean
        (void)level;
        (void)component;
        (void)message;
        // Optionally, store messages for specific tests if needed:
        // mutable std::vector<std::string> logged_messages;
        // logged_messages.push_back(message);
    }
};

// --- Test Fixture ---
class ConfigManagerTest : public ::testing::Test {
protected:
    netflow::ConfigManager configManager;
    DummySwitchLogger logger;
    std::string temp_filename;

    void SetUp() override {
        configManager.set_logger(&logger);
        // Generate a unique-ish temp filename for each test to avoid conflicts
        // Note: std::tmpnam is deprecated and unsafe. For robust testing, use mkstemp or C++17 filesystem.
        // For this environment, we'll use a fixed name and ensure cleanup.
        temp_filename = "temp_config_test_file.txt";
    }

    void TearDown() override {
        std::remove(temp_filename.c_str());
    }

    // Helper to create a temporary file with specific content
    bool create_temp_file_with_content(const std::string& filename, const std::string& content) {
        std::ofstream outfile(filename);
        if (!outfile.is_open()) {
            return false;
        }
        outfile << content;
        outfile.close();
        return true;
    }

    // Helper to read content from a file
    std::string read_file_content(const std::string& filename) {
        std::ifstream infile(filename);
        if (!infile.is_open()) {
            return "";
        }
        std::stringstream buffer;
        buffer << infile.rdbuf();
        return buffer.str();
    }
};

// --- Test Cases ---

TEST_F(ConfigManagerTest, LoadConfig_ValidSimpleFile) {
    std::string file_content =
        "path.to.bool=true\n"
        "path.to.int=123\n"
        "path.to.uint32=4294967295\n"
        "path.to.uint64=18446744073709551615\n"
        "path.to.double=123.456\n"
        "path.to.string=hello world\n";
    ASSERT_TRUE(create_temp_file_with_content(temp_filename, file_content));

    EXPECT_TRUE(configManager.load_config(temp_filename));

    EXPECT_EQ(configManager.get_parameter_as<bool>("path.to.bool").value_or(false), true);
    EXPECT_EQ(configManager.get_parameter_as<int>("path.to.int").value_or(0), 123);
    EXPECT_EQ(configManager.get_parameter_as<uint32_t>("path.to.uint32").value_or(0), 4294967295U);
    EXPECT_EQ(configManager.get_parameter_as<uint64_t>("path.to.uint64").value_or(0), 18446744073709551615ULL);
    EXPECT_DOUBLE_EQ(configManager.get_parameter_as<double>("path.to.double").value_or(0.0), 123.456);
    EXPECT_EQ(configManager.get_parameter_as<std::string>("path.to.string").value_or(""), "hello world");
}

TEST_F(ConfigManagerTest, LoadConfig_NonExistentFile) {
    EXPECT_FALSE(configManager.load_config("non_existent_file.txt"));
}

TEST_F(ConfigManagerTest, LoadConfig_InvalidFormat_NoEquals) {
    std::string file_content = "path.to.value true\n"; // Missing '='
    ASSERT_TRUE(create_temp_file_with_content(temp_filename, file_content));

    // The current load_config skips malformed lines. It should still return true if file opened.
    EXPECT_TRUE(configManager.load_config(temp_filename));
    EXPECT_FALSE(configManager.get_parameter("path.to.value true").has_value()); // Key should not be "path.to.value true"
    EXPECT_FALSE(configManager.get_parameter("path.to.value").has_value());   // Key should not be "path.to.value"
}

TEST_F(ConfigManagerTest, LoadConfig_EmptyFile) {
    std::string file_content = "";
    ASSERT_TRUE(create_temp_file_with_content(temp_filename, file_content));
    EXPECT_TRUE(configManager.load_config(temp_filename));
    EXPECT_TRUE(configManager.get_current_config_data().empty());
}

TEST_F(ConfigManagerTest, LoadConfig_CommentsAndWhitespace) {
    std::string file_content =
        "# This is a comment\n"
        "  key1 = value1  \n"
        "\n"
        "key2=value2 # Inline comment\n";
    ASSERT_TRUE(create_temp_file_with_content(temp_filename, file_content));
    EXPECT_TRUE(configManager.load_config(temp_filename));
    EXPECT_EQ(configManager.get_parameter_as<std::string>("key1").value_or(""), "value1");
    EXPECT_EQ(configManager.get_parameter_as<std::string>("key2").value_or(""), "value2 # Inline comment"); // Current parser includes inline comment as part of value
}


TEST_F(ConfigManagerTest, SetAndGetParameter) {
    configManager.set_parameter("test.bool", true);
    configManager.set_parameter("test.int", -42);
    configManager.set_parameter("test.uint32", static_cast<uint32_t>(12345));
    configManager.set_parameter("test.uint64", static_cast<uint64_t>(9876543210ULL));
    configManager.set_parameter("test.double", 3.14159);
    configManager.set_parameter("test.string", std::string("hello"));

    std::vector<uint32_t> vec_u32 = {1, 2, 3};
    configManager.set_parameter("test.vec_u32", vec_u32);
    std::vector<std::string> vec_str = {"a", "b", "c"};
    configManager.set_parameter("test.vec_str", vec_str);

    EXPECT_TRUE(configManager.get_parameter_as<bool>("test.bool").value_or(false));
    EXPECT_EQ(configManager.get_parameter_as<int>("test.int").value_or(0), -42);
    EXPECT_EQ(configManager.get_parameter_as<uint32_t>("test.uint32").value_or(0), 12345U);
    EXPECT_EQ(configManager.get_parameter_as<uint64_t>("test.uint64").value_or(0), 9876543210ULL);
    EXPECT_DOUBLE_EQ(configManager.get_parameter_as<double>("test.double").value_or(0.0), 3.14159);
    EXPECT_EQ(configManager.get_parameter_as<std::string>("test.string").value_or(""), "hello");

    EXPECT_EQ(configManager.get_parameter_as<std::vector<uint32_t>>("test.vec_u32").value_or(std::vector<uint32_t>()), vec_u32);
    EXPECT_EQ(configManager.get_parameter_as<std::vector<std::string>>("test.vec_str").value_or(std::vector<std::string>()), vec_str);

    EXPECT_FALSE(configManager.get_parameter("non.existent.key").has_value());
    EXPECT_FALSE(configManager.get_parameter_as<int>("non.existent.key").has_value());
}

TEST_F(ConfigManagerTest, SaveAndLoadConfig) {
    configManager.set_parameter("save.bool", true);
    configManager.set_parameter("save.int", 777);
    configManager.set_parameter("save.string", "save me");
    // Vectors are currently not saved by the basic save_config logic in ConfigManager.hpp
    // configManager.set_parameter("save.vec_u32", std::vector<uint32_t>{10,20});


    EXPECT_TRUE(configManager.save_config(temp_filename));

    netflow::ConfigManager newConfigManager;
    newConfigManager.set_logger(&logger);
    EXPECT_TRUE(newConfigManager.load_config(temp_filename));

    EXPECT_EQ(newConfigManager.get_parameter_as<bool>("save.bool").value_or(false), true);
    EXPECT_EQ(newConfigManager.get_parameter_as<int>("save.int").value_or(0), 777);
    EXPECT_EQ(newConfigManager.get_parameter_as<std::string>("save.string").value_or(""), "save me");
    // EXPECT_FALSE(newConfigManager.get_parameter("save.vec_u32").has_value()); // Since vectors aren't saved
}

TEST_F(ConfigManagerTest, ValidateConfig_Valid) {
    netflow::ConfigurationData data;
    data["port.1.speed_mbps"] = static_cast<uint32_t>(1000);
    data["some.other.key"] = std::string("value");

    std::vector<std::string> errors = configManager.validate_config(data);
    EXPECT_TRUE(errors.empty());
}

TEST_F(ConfigManagerTest, ValidateConfig_InvalidKey) {
    netflow::ConfigurationData data;
    data[""] = std::string("some value"); // Empty key

    std::vector<std::string> errors = configManager.validate_config(data);
    EXPECT_FALSE(errors.empty());
    EXPECT_NE(std::find(errors.begin(), errors.end(), "Configuration key cannot be empty."), errors.end());
}

TEST_F(ConfigManagerTest, ValidateConfig_InvalidTypeForKey) {
    netflow::ConfigurationData data;
    data["port.1.speed_mbps"] = std::string("1000Mbps"); // Should be uint32_t or int

    std::vector<std::string> errors = configManager.validate_config(data);
    EXPECT_FALSE(errors.empty());
    bool found_error = false;
    for(const auto& err : errors) {
        if (err.find("Invalid type for key 'port.1.speed_mbps'") != std::string::npos) {
            found_error = true;
            break;
        }
    }
    EXPECT_TRUE(found_error);
}

// int main(int argc, char **argv) {
//     ::testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }

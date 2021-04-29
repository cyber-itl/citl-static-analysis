#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>

#include "json.hpp"
#include "gflags/gflags.h"
#include "glog/logging.h"

#include "Driver.hpp"
#ifdef SECCOMP
#include "SecComp.hpp"
#endif
#include "meta.hpp"

using json = nlohmann::json;

DEFINE_string(binfile, "", "input binary to analyze");
DEFINE_string(test, "", "Toggles the test mode, tests output of current binary against supplied json string path");
DEFINE_bool(citl_data_identify, false, "Toggle json elements for citl-data parsing");


void test_bin(json binary, json old_binary) {
    CHECK(binary["bin_name"] == old_binary["bin_name"]) << "Invalid call to test_bin, bin_names do not match: new: " << binary["bin_name"] << " old: " << old_binary["bin_name"];

    for (json::iterator it = old_binary.begin(); it != old_binary.end(); ++it) {
        auto new_elm = binary.find(it.key());
        CHECK(new_elm != binary.end()) << "Failed to find key: " << it.key() << " in new results";

        CHECK(new_elm.value() == it.value()) << "Key: " << it.key() << " differs. new: " << new_elm.value() << " old: " << it.value();
    }

    // Check for any new fields in the output
    for (json::iterator it = binary.begin(); it != binary.end(); ++it) {
        auto new_elm = old_binary.find(it.key());
        CHECK(new_elm != old_binary.end()) << "New key in output, missing from old data: " << it.key();
    }
}

void test_binaries(json results, json old_results) {
    CHECK(results.is_array()) << "new 'binaries' results are not an array";
    CHECK(old_results.is_array()) << "old 'binaries' results are not an array";

    CHECK(results.size() == old_results.size()) << "binaries count does not match: new count: " << results.size() << " old count: " << old_results.size();

    if (old_results.size() == 1) {
        test_bin(results.at(0), old_results.at(0));
        return;
    }

    // Key results off of "bin_name"
    for (const auto &binary : old_results) {
        std::string bin_name = binary["bin_name"];

        auto it = std::find_if(results.begin(), results.end(), [bin_name](json elm)->bool { return elm["bin_name"] == bin_name; });

        CHECK(it != results.end()) << "Failed to find bin_name: " << bin_name << " in new results";

        test_bin(*it, binary);
    }
}

void test_json(json results, const std::string &json_file) {
    std::ifstream json_stream(json_file);
    json old_results;
    json_stream >> old_results;

    CHECK(old_results.size() > 0) << "No results found in json file: " << json_file;

    for (json::iterator it = old_results.begin(); it != old_results.end(); ++it) {
        if (it.key() == "binaries") {
            auto new_bins = results.find(it.key());
            CHECK(new_bins != results.end()) << "New results do not have a binaries section";

            test_binaries(new_bins.value(), it.value());
            continue;
        }

        // Skip the volitile git sha1 hash
        if (it.key() == "git_commit") {
            continue;
        }

        auto new_res = results.find(it.key());
        CHECK(new_res != results.end()) << "Old results do not have the key: " << it.key();

        CHECK(new_res.value() == it.value()) << "Element: " << it.key() << "does not match, new: " << it.value() << " old: " << new_res.value();
    }
}

int main(int argc, char **argv)
{
    google::SetUsageMessage("citl-static-main");
    google::InitGoogleLogging(argv[0]);
    google::ParseCommandLineFlags(&argc, &argv, true);

    if (FLAGS_citl_data_identify) {
        std::cout << R"({"tool": "citl-static-analysis", "commit": ")" << git_commit_sha1 << R"("})" << std::endl;
        return 0;
    }

    if (!FLAGS_binfile.size()) {
        LOG(ERROR) << "Please supply a -binfile";
        return 1;
    }

#ifdef SECCOMP
    if (setup_seccomp()) {
        LOG(ERROR) << "SecComp setup failed";
        return 1;
    }
#endif


    Driver analyzer = Driver(FLAGS_binfile);

    if (analyzer.analyze()) {
        LOG(ERROR) << "Failed to analyze input binary: " << FLAGS_binfile;
        return 1;
    }

    if (!FLAGS_test.empty()) {
        test_json(analyzer.get_results(), FLAGS_test);
    }
    else {
        analyzer.print();
    }
    return 0;
}

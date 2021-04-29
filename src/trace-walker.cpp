#include <iostream>
#include <string>

#include "gflags/gflags.h"
#include "glog/logging.h"

#include "TraceManager.hpp"

DEFINE_string(bindir, "", "Input directory of binaries, filenames should be modid's: ex: dir/1.bin");
DEFINE_string(corpus, "", "Input corpus directory of traces");
DEFINE_string(trace, "", "Input path to single testcase file to process");
DEFINE_string(analyzer, "", "Name of analyzer to run on trace(s)");
DEFINE_uint32(threads, 4, "Number of threads to use for the thread pool");


int main(int argc, char **argv)
{
    google::SetUsageMessage("trace-template");
    google::InitGoogleLogging(argv[0]);
    google::ParseCommandLineFlags(&argc, &argv, true);

    if (FLAGS_analyzer.empty()) {
        LOG(ERROR) << "Please supply an analyzer name (-analyzer <name>)";
        return 1;
    }

    if (FLAGS_bindir.empty()) {
        LOG(ERROR) << "Please supply an input directory (-bindir <path>)";
        return 1;
    }

    if (!exists(FLAGS_bindir, true)) {
        LOG(ERROR) << "Failed to find DIR: " << FLAGS_bindir;
        return 1;
    }

    if ((FLAGS_corpus.empty() && FLAGS_trace.empty()) || (!FLAGS_corpus.empty() && !FLAGS_trace.empty())) {
        LOG(ERROR) << "Please select either -trace or -corpus";
        return 1;
    }

    auto manager = TraceManager(FLAGS_bindir);
    if (!manager.create_mod_map()) {
        return 1;
    }

    if (!FLAGS_trace.empty()) {
        if (!exists(FLAGS_trace, false)) {
            LOG(ERROR) << "Failed to find trace file: " << FLAGS_trace;
            return 1;
        }
        manager.process_testcase(FLAGS_trace, FLAGS_analyzer);
    }
    else if (!FLAGS_corpus.empty()) {
        manager.process_corpus(FLAGS_corpus, FLAGS_analyzer, FLAGS_threads);
    }

    return 0;
}

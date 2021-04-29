#pragma once

#include <string>
#include <vector>

namespace elf_funcs {
extern std::vector<std::string> good_funcs;
extern std::vector<std::string> risky_funcs;
extern std::vector<std::string> bad_funcs;
extern std::vector<std::string> ick_funcs;
}

namespace pe_funcs {
extern std::vector<std::string> good_funcs;
extern std::vector<std::string> risky_funcs;
extern std::vector<std::string> bad_funcs;
extern std::vector<std::string> ick_funcs;
}

namespace macho_funcs {
extern std::vector<std::string> good_funcs;
extern std::vector<std::string> risky_funcs;
extern std::vector<std::string> bad_funcs;
extern std::vector<std::string> ick_funcs;
}

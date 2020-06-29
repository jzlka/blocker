/**
 *  @file       exchange_data.cpp
 *  @brief      Brief description
 *  @author     Jozef Zuzelka <jozef.zuzelka@gmail.com>
 *  @date
 *   - Created: 29.06.2020 13:50
 *   - Edited:  29.06.2020 14:00
 *  @version    1.0.0
 *  @par        gcc: Apple clang version 11.0.3 (clang-1103.0.32.62)
 *  @bug
 *  @todo
 */

#include <unistd.h>
#include <sys/attr.h>
#include <iostream>

int main(const int argc, const char * const argv[])
{
    if (argc != 3) {
        std::cerr << "Expected two arguments: " << argv[0] << " <file1> <file2>\n";
        return EXIT_FAILURE;
    }

    if (exchangedata(argv[1], argv[2], 0)) {
        perror("exchangedata failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}



/* vim: set ts=4 sw=4 tw=0 et :*/

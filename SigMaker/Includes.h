#pragma once

#define _CRT_SECURE_NO_WARNINGS 1
#define __IDP__                 1
#define __NT__                  1
#define __X64__                 1

#pragma warning( push )  
#pragma warning( disable : 4267 )
#pragma warning( disable : 4244 )
#include <expr.hpp>
#include <loader.hpp>
#include <search.hpp> // find_binary
#include <diskio.hpp>
#pragma warning( pop ) 

#pragma comment(lib, "ida.lib")
#pragma comment(lib, "pro.lib")
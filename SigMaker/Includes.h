#pragma once

#define _CRT_SECURE_NO_WARNINGS 1
#define __IDP__                 1
#define __NT__                  1
#define __X64__                 1

#pragma warning( push )  
#pragma warning( disable : 4267 )
#pragma warning( disable : 4244 )
#include <ida.hpp>
#include <idp.hpp>
#include <enum.hpp>
#include <frame.hpp> 
#include <expr.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <bytes.hpp>
#include <struct.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>
#include <allins.hpp>
#include <search.hpp> // find_binary
#include <ua.hpp>
#include <fpro.h>
#include <diskio.hpp>
#pragma warning( pop ) 

#pragma comment(lib, "ida.lib")
#pragma comment(lib, "pro.lib")
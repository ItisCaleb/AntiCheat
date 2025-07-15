// ACLib.cpp : Defines the functions for the static library.
//

#include "anti_cheat.h"
#include <Windows.h>
#include <debugapi.h>
#include <stdio.h>
#include <stdlib.h>
// TODO: This is an example of a library function
void AntiCheat::init() {
	if (IsDebuggerPresent()) {
		printf("No Debugger\n!");
		exit(1);
	}
}

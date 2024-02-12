#include "Ejector.hpp"

int main(void) {
	ejector ej;

	ej.SetEjectDLL(L"notepad.exe", L"test.dll");
	return 0;
};
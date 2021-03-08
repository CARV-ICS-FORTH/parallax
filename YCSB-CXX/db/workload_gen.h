#include <cassert>
#include <iostream>
#include <string>
#ifndef __WORKLOAD_GEN_H_
#define __WORKLOAD_GEN_H_
int return_wl(std::string &wl)
{
	if (wl == "sd")
		return 0;
	else if (wl == "md")
		return 1;
	else if (wl == "ld")
		return 2;
	else if (wl == "s")
		return 3;
	else if (wl == "m")
		return 4;
	else if (wl == "l")
		return 5;
	else {
		std::cout << "Error unknown workload specified" << std::endl;
		assert(0);
		exit(EXIT_FAILURE);
	}
}

int choose_wl(std::string &wl, const int &x)
{
	switch (return_wl(wl)) {
	case 0:
		if (x < 6)
			return 0;
		else if (x >= 6 && x < 8)
			return 1;
		else
			return 2;

		break;
	case 1:
		if (x < 6)
			return 1;
		else if (x >= 6 && x < 8)
			return 0;
		else
			return 2;

		break;
	case 2:
		if (x < 6)
			return 2;
		else if (x >= 6 && x < 8)
			return 0;
		else
			return 1;

		break;
	case 3:
		return 0;
	case 4:
		return 1;
	case 5:
		return 2;
	default:
		assert(0);
		std::cout << "Unknown workload given" << std::endl;
		exit(EXIT_FAILURE);
	}
	exit(EXIT_FAILURE);
}

#endif // __WORKLOAD_GEN_H_

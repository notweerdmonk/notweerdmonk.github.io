#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		int i;
		while (file) {
			file >> i;
			std::cout << i << ' ';
		}
		std::cout << std:: endl;
	}
	return 0;
}

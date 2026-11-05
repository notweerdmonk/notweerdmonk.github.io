#include <iostream>
#include <fstream>
#include <sstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		std::string line;
		while (std::getline(file, line)) {
			int i;
			std::istringstream iss{line};
			while (iss >> i) {
				if (
						(std::isspace(iss.peek()) && iss >> std::ws) ||
						iss.peek() == std::char_traits<char>::eof()
				) {
						std::cout << i << '\n';
				} else {
					std::cerr << "Not an integer\n";
				}
			}
		}
	}
	return 0;
}

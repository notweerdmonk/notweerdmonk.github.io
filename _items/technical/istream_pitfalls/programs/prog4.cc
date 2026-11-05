#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		int i;
		while (file >> i) {
			std::ifstream::int_type ch = file.get();
			if (
					file >> std::ws &&
					file.peek() == std::char_traits<char>::eof()
			) {
				std::cout << i << '\n';
			} else {
				std::cerr << "Not an integer\n";
			}
		}
	}
	return 0;
}

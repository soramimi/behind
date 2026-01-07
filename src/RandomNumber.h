#ifndef RANDOMNUMBER_H
#define RANDOMNUMBER_H

#include <random>

class RandomNumber {
public:
	std::random_device rd;
	std::mt19937 gen;
	RandomNumber()
		: gen(rd())
	{
	}
};

#endif // RANDOMNUMBER_H

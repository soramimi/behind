#ifndef RANDOMNUMBERGENERATOR_H
#define RANDOMNUMBERGENERATOR_H

#include <cstdint>
#include <cstdlib>

class RandomNumberGenerator {
private:
	struct Private;
	Private *m;

public:
	RandomNumberGenerator();
	~RandomNumberGenerator();
	uint32_t next_u32();
};

#endif // RANDOMNUMBERGENERATOR_H

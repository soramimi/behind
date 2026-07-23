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
	uint16_t next_txid();
	uint32_t next_u32();
	uint16_t random_port();
};

#endif // RANDOMNUMBERGENERATOR_H

#include "RandomNumberGenerator.h"
#include "ChaCha20.h"
#include <numeric>
#include <utility>

struct RandomNumberGenerator::Private {
	ChaCha20 chacha20;
};

RandomNumberGenerator::RandomNumberGenerator()
	: m(new Private)
{
}

RandomNumberGenerator::~RandomNumberGenerator()
{
	delete m;
}

uint32_t RandomNumberGenerator::next_u32()
{
	return m->chacha20.next_u32();
}



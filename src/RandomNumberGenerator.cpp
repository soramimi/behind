#include "RandomNumberGenerator.h"
#include "ChaCha20.h"
#include <numeric>
#include <utility>

struct RandomNumberGenerator::Private {
	uint16_t pool[65536];
	int index = 0;
	ChaCha20 chacha20;
};

RandomNumberGenerator::RandomNumberGenerator()
	: m(new Private)
{
	std::iota(m->pool, m->pool + 65536, 0);
	// Proper Fisher-Yates: pick j from [i, 65536) so every permutation is
	// equally likely (the previous full-range pick was slightly biased).
	for (int i = 0; i < 65535; ++i) {
		int j = i + (int)(m->chacha20.next_u32() % (uint32_t)(65536 - i));
		std::swap(m->pool[i], m->pool[j]);
	}
}

RandomNumberGenerator::~RandomNumberGenerator()
{
	delete m;
}

uint16_t RandomNumberGenerator::next_txid()
{
	int i = (m->index + (m->chacha20.next_u32() & 0x7fff)) & 0xffff;
	std::swap(m->pool[m->index], m->pool[i]);
	uint16_t id = m->pool[m->index];
	m->index = (m->index + 1) & 0xffff;
	return id;
}

uint32_t RandomNumberGenerator::next_u32()
{
	return m->chacha20.next_u32();
}

uint16_t RandomNumberGenerator::random_port()
{
	// IANA dynamic/ephemeral range 49152..65535 (RFC 6056). The range width
	// is 16384 = 2^14, which divides 2^32 evenly, so masking is unbiased.
	return (uint16_t)(49152 + (m->chacha20.next_u32() & 0x3fff));
}

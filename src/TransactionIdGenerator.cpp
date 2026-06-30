#include "TransactionIdGenerator.h"

#include "RandomNumber.h"
#include <limits>

struct TransactionIdGenerator::Private {
	RandomNumber random;
	std::uniform_int_distribution<int> dist64k;
	std::uniform_int_distribution<int> dist32k;
	std::uniform_int_distribution<uint32_t> dist32bit;
	std::uniform_int_distribution<int> distport;
	uint16_t pool[65536];
	int index = 0;

	Private()
		: dist64k(0, 0xffff)
		, dist32k(0, 0x7fff)
		, dist32bit(0, std::numeric_limits<uint32_t>::max())
		, distport(1024, 65535)
	{
	}
};

TransactionIdGenerator::TransactionIdGenerator()
	: m(new Private)
{
	std::iota(m->pool, m->pool + 65536, 0);
	for (int i = 0; i < 65536; ++i) {
		int j = m->dist64k(m->random.gen);
		std::swap(m->pool[i], m->pool[j]);
	}
}

TransactionIdGenerator::~TransactionIdGenerator()
{
	delete m;
}

uint16_t TransactionIdGenerator::next()
{
	int i = (m->index + m->dist32k(m->random.gen)) & 0xffff;
	std::swap(m->pool[m->index], m->pool[i]);
	uint16_t id = m->pool[m->index];
	m->index = (m->index + 1) & 0xffff;
	return id;
}

uint32_t TransactionIdGenerator::next_u32()
{
	return m->dist32bit(m->random.gen);
}

uint16_t TransactionIdGenerator::random_port()
{
	return (uint16_t)m->distport(m->random.gen);
}

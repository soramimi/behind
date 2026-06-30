#ifndef TRANSACTIONIDGENERATOR_H
#define TRANSACTIONIDGENERATOR_H

#include <cstdint>
#include <cstdlib>

class TransactionIdGenerator {
private:
	struct Private;
	Private *m;
public:
	TransactionIdGenerator();
	~TransactionIdGenerator();
	uint16_t next();
	uint32_t next_u32();
	uint16_t random_port();
};

#endif // TRANSACTIONIDGENERATOR_H

#ifndef TRANSACTIONIDGENERATOR_H
#define TRANSACTIONIDGENERATOR_H

#include <cstdint>
#include <cstdlib>
#include <random>

class TransactionIdGenerator {
private:
	struct Private;
	Private *m;
public:
	TransactionIdGenerator();
	~TransactionIdGenerator();
	uint16_t next();
};

#endif // TRANSACTIONIDGENERATOR_H

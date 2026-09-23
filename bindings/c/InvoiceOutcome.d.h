#ifndef InvoiceOutcome_D_H
#define InvoiceOutcome_D_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"





typedef enum InvoiceOutcome {
  InvoiceOutcome_Unknown = 0,
  InvoiceOutcome_Accepted = 1,
  InvoiceOutcome_Rejected = 2,
} InvoiceOutcome;

typedef struct InvoiceOutcome_option {union { InvoiceOutcome ok; }; bool is_ok; } InvoiceOutcome_option;



#endif // InvoiceOutcome_D_H

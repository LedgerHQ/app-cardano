#ifndef H_CARDANO_APP_IO
#define H_CARDANO_APP_IO

#include <os_io_seproxyhal.h>
#include <stdint.h>

// io_send_* arehelper functions for sending response APDUs.
// Note that the IO_RETURN_AFTER_TX flag is set so that the function
// does not receive next APDU.
// 'tx' is the conventional name for the size of the response APDU,
// i.e. the write-offset within G_io_apdu_buffer.

void io_send_code(uint16_t code, uint16_t tx);

void io_send_buf(uint16_t code, uint8_t* buffer, uint16_t len);

// Asserts that the response fits into response buffer
void CHECK_RESPONSE_SIZE(unsigned int tx);


// Everything below this point is Ledger magic

void io_seproxyhal_display(const bagl_element_t *element);
unsigned char io_event(unsigned char channel);

#endif
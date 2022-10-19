#ifndef H_CARDANO_APP_UI_H
#define H_CARDANO_APP_UI_H

#include "io.h"
#include "uiHelpers.h"

#ifdef HAVE_NBGL
typedef void (*callback_t)(void);

void fill_and_display_if_required(const char* line1, const char* line2, callback_t user_accept_cb, callback_t user_reject_cb);
void fill_and_display_new_page(const char* line1, const char* line2, callback_t user_accept_cb, callback_t user_reject_cb);
void finish_display(callback_t user_accept_cb, callback_t user_reject_cb);
void display_confirmation(const char* text1, const char* text2, const char* confirmText, const char* rejectText, callback_t user_accept_cb, callback_t user_reject_cb);
void display_page(callback_t user_accept_cb, callback_t user_reject_cb);
void display_prompt(const char* text1, const char* text2, callback_t user_accept_cb, callback_t user_reject_cb);
void display_warning(const char* text, callback_t user_accept_cb, callback_t user_reject_cb);
void display_continue(callback_t user_accept_cb);
void ui_idle(void);
#endif

#ifdef HAVE_BAGL
void io_seproxyhal_display(const bagl_element_t *element);
#endif // HAVE_BAGL

#endif // H_CARDANO_APP_UI_H
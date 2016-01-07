/* ========================================================================
 * Copyright (c) 2010 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

#ifndef _preauth_h_
#define _preauth_h_

#ifndef LDAP_VERSION
#define LDAP void
#endif

#include <regex.h>

/* long string */
typedef struct LongString__ {
  char *buf;
  int pos;
  int len;
  int ptr;
} LongString_, *LongString;

#define LONGSTRING_INC 8192

LongString newLongString();
void catnLongString(LongString ls, char *s, int l);
void catLongString(LongString ls, char *s);
void clearLongString(LongString ls);
void freeLongString(LongString ls);

#define VERIFY_NONE  0
#define VERIFY_GWS   1   // group web service
#define VERIFY_ADS   2   // pds ldap account branch

#define FAIL_ALLOW   1
#define FAIL_DENY    2

typedef struct Restriction__ {
   struct Restriction__ *next;
   char *name;
   int verify_type;
   int fail_mode;
   char *verify_data;
   char *redirect_url;
   char *return_name;
   regex_t **regex_list;
   char *retry_name;
   char *retry_param;
} Restriction_, *Restriction;

typedef struct Env__ {
  char *gws_crt;
  char *gws_key;
  char *gws_ca;
  char *gws_url_template;
  char *ads_host;
  char *ads_port;
  char *ads_crt;
  char *ads_key;
  char *ads_ca;
  char *ads_base;
  Restriction restrictions;

  char *remote_user;
  char *uri;
  char *qs;

  LDAP *ldap;

  char *proxd_host;
  char *proxd_service;
  char *proxd_app;
  char *proxd_level;

} Env_, *Env;


Env get_config();
int gws_is_member(Env E, char *group_name, char *id);
int gws_init();
int ads_has_subscription(Env E, char *sub, char *id);
LDAP *ads_init(Env E);
int proxd_alert(char *smsg, char *lmsg);

#endif // _preauth_h_

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

/* webservice tools for idp preauth */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#include "preauth.h"

LongString newLongString()
{
   LongString ls = (LongString) malloc(sizeof(LongString_));
   ls->buf = (char*) malloc(LONGSTRING_INC);
   ls->pos = 0;
   ls->ptr = 0;
   ls->len = LONGSTRING_INC;
   ls->buf[0] = '\0';
   return (ls);
}

void catnLongString(LongString ls, char *s, int l)
{
   if (ls->pos+l >= ls->len) {
      ls->len += LONGSTRING_INC;
      ls->buf = (char*) realloc(ls->buf, ls->len);
   }
   strncpy(ls->buf+ls->pos, s, l);
   ls->pos += l;
   ls->buf[ls->pos] = '\0';
}

void catLongString(LongString ls, char *s)
{
   int l = strlen(s);
   catnLongString(ls, s, l);
}

void clearLongString(LongString ls)
{
   ls->pos = 0;
   ls->ptr = 0;
   ls->buf[ls->pos] = '\0';
}

void freeLongString(LongString ls)
{
   free(ls->buf);
   free(ls);
}

CURL *curl;

LongString curl_data; 

/* --- curl tools --- */

static size_t page_reader(void *buf, size_t len, size_t num, void *wp)
{
  // PRINTF("..recv %d(%d) bytes\n", len, num);
  // page_buf = mystrncat(page_buf, buf, len*num);
  catnLongString(curl_data, buf, len*num);
  return (len*num);
}
static size_t header_reader(void *buf, size_t len, size_t num, void *wp)
{
  // PRINTF("..head %d(%d) bytes: [%s]\n", len, num, buf);
  // PRINTF( "data: %s\n", buf);
  return (len*num);
}


// ret 1 in group, 0 not in group, -1 system failure
int gws_is_member(Env E, char *group_name, char *member_id)
{
   char error[CURL_ERROR_SIZE];
   char url[2048];
   int s;
   int http_resp;
   int nb;
 
   snprintf(url, 2047, E->gws_url_template, group_name, member_id);
   error[0] = '\0';
   curl_easy_setopt(curl, CURLOPT_URL, url);

   s = curl_easy_perform(curl);
   curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_resp);
   if (http_resp==200) return (1);
   if (http_resp!=404) {
      syslog(LOG_ERR, "curl error response: %d\n", http_resp);
      return (-1);
   }
   return(0);
}

int gws_init()
{

   curl = curl_easy_init();
   curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_reader);
   curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
   struct curl_slist *headers=NULL;
   headers = curl_slist_append(headers, "Accept: text/xml");
   curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
   // curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errtxt);

   curl_data = newLongString();
   
}


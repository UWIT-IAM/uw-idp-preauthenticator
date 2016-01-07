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

/* idp preauth - config */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netdb.h>

#include "preauth.h"


Env newEnv()
{
   Env E = (Env) malloc(sizeof(Env_));
   memset(E, 0, sizeof(Env_));
   return (E);
}

Restriction newRestriction()
{
   Restriction R = (Restriction) malloc(sizeof(Restriction_));
   memset(R, 0, sizeof(Restriction_));
   R->regex_list = (regex_t**) malloc(sizeof(regex_t*));
   *R->regex_list = NULL;
   return (R);
}

Env get_config(char *file)
{
   FILE *fp;
   Env E;
   Restriction R = NULL;
   int nregex = 0;
   char rec[256];

   if (!(fp=fopen(file,"r"))) {
      return (NULL);
   }
   E = newEnv();

   
   // parse "key = value" lines
   while (fgets(rec, 255, fp)) {
      char *k = rec;
      char *p, *q, *r;
      int rxn = 0;

      // parse the key = value
      if (p=strchr(rec,'\n')) *p = '\0';
      while (*k && isspace(*k)) k++;
      if (*k=='#') continue;
      // k is key
      for (p=k; *p && !isspace(*p); p++);
      *p++ = '\0';
      while (*p && (isspace(*p)||(*p=='='))) p++;
      // p is value
      for (q=p; *q && !isspace(*q); q++);
      if (*q) *q++ = '\0';
      while (*q && isspace(*q)) q++;
      // q is 2nd value
      for (r=q; *r && !isspace(*r); r++);
      if (*r) *r++ = '\0';

      if (!strcmp(k,"gws_crt")) E->gws_crt = strdup(p);
      else if (!strcmp(k,"gws_key")) E->gws_key = strdup(p);
      else if (!strcmp(k,"gws_ca")) E->gws_ca = strdup(p);
      else if (!strcmp(k,"gws_url_template")) E->gws_url_template = strdup(p);
      else if (!strcmp(k,"ads_host")) E->ads_host = strdup(p);
      else if (!strcmp(k,"ads_port")) E->ads_port = strdup(p);
      else if (!strcmp(k,"ads_crt")) E->ads_crt = strdup(p);
      else if (!strcmp(k,"ads_key")) E->ads_key = strdup(p);
      else if (!strcmp(k,"ads_ca")) E->ads_ca = strdup(p);
      else if (!strcmp(k,"ads_base")) E->ads_base = strdup(p);
      else if (!strcmp(k,"proxd_host")) E->proxd_host = strdup(p);
      else if (!strcmp(k,"proxd_service")) E->proxd_service = strdup(p);
      else if (!strcmp(k,"proxd_app")) E->proxd_app = strdup(p);
      else if (!strcmp(k,"proxd_level")) E->proxd_level = strdup(p);
      else if (!strcmp(k,"restriction")) {
         if (R) {
            R->next = E->restrictions;
            E->restrictions = R;
         } 
         R = newRestriction();
         R->name = strdup(p);
         nregex = 0;
      } else if (!strcmp(k,"verify_type")) {
         if (!strcmp(p, "gws")) R->verify_type = VERIFY_GWS;
         else if (!strcmp(p, "ads")) R->verify_type = VERIFY_ADS;
         else {
            fprintf(stderr, "invalid verify type '%s'\n", p);
            continue;
         }
      } else if (!strcmp(k,"fail_mode")) {
         if (!strcmp(p, "allow")) R->fail_mode = FAIL_ALLOW;
         else if (!strcmp(p, "deny")) R->fail_mode = FAIL_DENY;
         else {
            fprintf(stderr, "invalid fail mode '%s'\n", p);
            continue;
         }
      } else if (!strcmp(k,"group")) R->verify_data = strdup(p); 
      else if (!strcmp(k,"subscription")) R->verify_data = strdup(p); 
      else if (!strcmp(k,"redirect_url")) R->redirect_url = strdup(p);
      else if (!strcmp(k,"return_name")) R->return_name = strdup(p);
      else if (!strcmp(k,"retry_name")) R->retry_name = strdup(p);
      else if (!strcmp(k,"retry_param")) R->retry_param = strdup(p);
      else if (!strcmp(k,"regex")) {
         regex_t *rx = (regex_t *) malloc(sizeof(regex_t));;
         R->regex_list = (regex_t**) realloc(R->regex_list, (nregex+1)*sizeof(regex_t*));
         int ret = regcomp(rx, p, REG_NOSUB);
         if (ret!=0) {
            fprintf(stderr, "could not compile '%s'\n", p);
            continue;
         }
         *(R->regex_list+nregex++) = rx;
         *(R->regex_list+nregex) = NULL;
      }
   }
   if (R) {
      R->next = E->restrictions;
      E->restrictions = R;
   } 

   fclose(fp);
   return (E);
}



 

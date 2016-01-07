/* ========================================================================
 * Copyright (c) 2008 The University of Washington
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


/* GWS pre-authenticator */

#ifdef WITH_FCGI
#include "fcgi_stdio.h"
#define MAX_REQUESTS 1000
#else
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>

#include "preauth.h"


int we_are_active = 0;

/* TERM signal means apache really wants us to quit. */
int term_requested = 0;
static void catch_term(int a)
{
   if (we_are_active) {
      term_requested = 1;
   } else {
      syslog(LOG_INFO, "exit request while idle");
      exit (0);
   }
}
static void catch_signals()
{
   signal(SIGTERM, catch_term);
   signal(SIGUSR1, catch_term);
   signal(SIGPIPE, SIG_IGN);
   term_requested = 0;
}

// response template
char *html_top = "\
Cache-Control: no-store, no-cache, must-revalidate\n\
Expires: Sat, 1 Jan 2000 01:01:01 GMT\n\
Pragma: No-Cache\n\
Cache-Control: max-age=-8705554\n\
Content-type: text/html\n\
";

// end of response header
char *html_bot = "\
\n\n\
<html><body><META HTTP-EQUIV=REFRESH CONTENT=\"0; URL=%s\"><a href=\"%s\">continue</a></body></html>\n\
";

/* make the return url as a qs parameter */
char *make_qs_url(Env E)
{
   int na = 0;
   int i;
   char *ret;
   char *s, *r;
   for (s=strchr(E->uri,'&'); s; s=strchr(s+1, '&')) na++;
   for (s=strchr(E->qs,'&'); s; s=strchr(s+1, '&')) na++;
   for (s=strchr(E->qs,'%'); s; s=strchr(s+1, '%')) na++;
   ret = (char*) malloc(strlen(E->uri)+strlen(E->qs)+na*4+32);

   for (r=ret,s=E->uri; *s; s++) {
      if (*s=='&') *r++='%',*r++='2',*r++='6';
      else *r++ = *s;
   }
   *r++ = '?';
   for (s=E->qs; *s; s++) {
      if (*s=='&') *r++='%',*r++='2',*r++='6';
      else if (*s=='%') *r++='%',*r++='2',*r++='5';
      else *r++ = *s;
   }
   strcpy(r, "%26preauth=verified");
   return (ret);
}

/* make the retry parameter 
   uudecodes one level
   returns "" if not found */

char *make_retry_param(Env E, Restriction R)
{
   int na = 0;
   int i;
   char *ret;
   char *s, *r;
   char *p;
   char penc[256];

   if (!(R->retry_param&&R->retry_name)) return (strdup(""));
   snprintf(penc, 256, "%%26%s%%3D", R->retry_param);
   if (!(s=strstr(E->qs, penc))) return (strdup(""));
   s = strstr(s, "%3D") + 3;
   if (!(r=strstr(s, "%26"))) r = s + strlen(s);
   ret = (char*) malloc(r - s  + strlen(R->retry_name) + 8);

   sprintf(ret, "&%s=", R->retry_name);
   for (p=ret; *p; p++);
   // copy the retry url
   while (s<r) {
      if (!strncasecmp(s, "%25", 3)) {
         *p++ = '%';
         s += 3;
      } else *p++ = *s++;
   }
   *p = '\0';
   return (ret);
}

// redirect to continue the shib login
int no_action_response(Env E, char *msg)
{
   char url[8192];
   snprintf(url, 8192, "%s?%s&preauth=verified", E->uri, E->qs);
   syslog(LOG_INFO, "Login as usual for '%s': %s", E->remote_user, msg);
//    syslog(LOG_DEBUG, "out url = %s", E->uri);

   printf(html_top);
   printf("Refresh: 0; url=%s\n", url);
   printf(html_bot, url, url);

   return (200);
}

// redirect to interrupt the shib login
int action_response(Env E, Restriction R)
{
   char url[8192];
   char *returl = make_qs_url(E);
   char *retprm = make_retry_param(E, R);
   char sep = '?';
   if (strchr(R->redirect_url, '?')) sep = '&';
   snprintf(url, 8192, "%s%c%s=%s%s\n", R->redirect_url, sep, R->return_name, returl, retprm);

   syslog(LOG_INFO, "Preauthentication needed for '%s' for %s", E->remote_user, R->name);
   syslog(LOG_DEBUG, "  %s = %s", R->return_name, returl);
   if (*retprm) syslog(LOG_DEBUG, "  %s = %s", R->retry_name, retprm);

   printf(html_top);
   printf("Refresh: 0; url=%s\n", url);
   printf(html_bot, url, url);

   free(returl);
   free(retprm);
   return (200);
}

int main(int argc, char** argv)
{
   int noerr = 1;
   int resp = 0;
   Env E;
   Restriction R;
   regex_t **rx;

   openlog("idp_preauth", LOG_PID, LOG_LOCAL6);
   syslog(LOG_INFO, "starting");
   catch_signals();
   

   E = get_config("etc/preauth.conf");

   proxd_init(E);
   if (E->gws_url_template) gws_init(E);
   if (E->ads_host) ads_init(E);

#ifdef WITH_FCGI
   int total_requests = 0;
   while (FCGI_Accept() >= 0) {
#endif

      we_are_active = 1;
      noerr = 1;

      E->remote_user = getenv("REMOTE_USER");
      if (!E->remote_user) {
         syslog(LOG_ALERT, "no remote_user??");
      }
      syslog(LOG_DEBUG, "activated for '%s'", E->remote_user);

      // syslog(LOG_DEBUG, "request_uri: %s", getenv("REQUEST_URI"));
      // syslog(LOG_DEBUG, "script_uri: %s", getenv("SCRIPT_URI"));
      // syslog(LOG_DEBUG, "script_name: %s", getenv("SCRIPT_NAME"));

      E->uri = getenv("SCRIPT_URI");
      if (!E->uri) {
         syslog(LOG_ALERT, "no SCRIPT_URI??");
      }
      // syslog(LOG_DEBUG, "script_uri: %s", E->uri);

      E->qs = getenv("QUERY_STRING");
      if (!E->qs) {
         syslog(LOG_ALERT, "no QUERY_STRING??");
      }
      // syslog(LOG_DEBUG, "query_string: %s", E->qs);

      for (R=E->restrictions; R; R=R->next) {
         for (rx=R->regex_list;*rx;rx++) {
            int ret = regexec(*rx, E->qs, 0, NULL, 0);
            if (ret==0) break; // match
         }
         if (*rx) break;
      }
      if (R) {
         if (R->verify_type==VERIFY_GWS) {
            if ((resp=gws_is_member(E, R->verify_data, E->remote_user))>0) resp = no_action_response(E, "is member");
            else if (resp==0 ) resp = action_response(E, R);
            else if (R->fail_mode==FAIL_DENY) resp = action_response(E, R);
            else resp = no_action_response(E, "fail allow");
         } else if (R->verify_type==VERIFY_ADS) {
            if ((resp=ads_has_subscription(E, R->verify_data, E->remote_user))>0) resp = no_action_response(E, "has subscription");
            else if (resp==0 ) resp = action_response(E, R);
            else if (R->fail_mode==FAIL_DENY) resp = action_response(E, R);
            else resp = no_action_response(E, "fail allow");
         }
      } else {
         resp = no_action_response(E, "no match: not for me");
      }
 
      fflush(stdout);

#ifdef WITH_FCGI
      if (total_requests++>=MAX_REQUESTS) {
         syslog(LOG_INFO, "exit due to max requests reached: %d", total_requests);
         break;
      }
      if (term_requested) {
         syslog(LOG_INFO, "exit on term signal");
         break;
      }
      we_are_active = 0;
   }
#endif

   syslog(LOG_INFO, "exiting");
   exit (0);
}




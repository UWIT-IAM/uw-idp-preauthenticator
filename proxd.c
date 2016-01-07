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

/* idp preauthenticator: proxd interface */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <pthread.h>

#include "preauth.h"

int nproxderr = 0;
int proxd_sock;
struct sockaddr_in proxd_addr;
char my_hostname[64];
int proxd_level = 0;
char *proxd_app;

/* initialize the proxd sender */

int proxd_init(Env E)
{
   struct servent *sp;
   struct hostent *host;
   
   gethostname(my_hostname, 64);

   if (!(E->proxd_host&&E->proxd_service&&E->proxd_app)) {
      syslog(LOG_ERR, "invalid proxd configuration!");
      return (0);
   }
   proxd_sock = 0;
   proxd_addr.sin_family = AF_INET;
   host = gethostbyname(E->proxd_host);
   if (!host) {
       syslog(LOG_ERR, "couldn't get host for %s: %m", E->proxd_host);
       return (0);
   }
   proxd_addr.sin_family = host->h_addrtype;
   bcopy(host->h_addr, &proxd_addr.sin_addr, host->h_length);

   sp = getservbyname(E->proxd_service, "udp");
   if (!sp) {
       syslog(LOG_ERR, "couldn't get service for %s: %m", E->proxd_service);
       return (0);
   }
   proxd_addr.sin_port = sp->s_port;

   if ((proxd_sock = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
      syslog(LOG_ERR, "couldn't get proxd socket: %m");
      perror("socket");
      return (0);
   }

   if (E->proxd_level) proxd_level = atoi(E->proxd_level);
   if (proxd_level<=0) proxd_level = 1;
   proxd_app = strdup(E->proxd_app);
   return (1);
}

static char *proxd_upd_template = "<?xml version=\"1.0\" ?><transactionlist><transaction>\
<newAlert host=\"%s\" component=\"%s\" sev=\"%d\" msg=\"%s\" longmsg=\"%s\" contact=\"oncall\" count=\"+\"/>\
</transaction></transactionlist>";

int proxd_alert(char *smsg, char *lmsg)
{
   char buf[1024];
   int nb;

   if (!proxd_sock) return (0);

   snprintf(buf, 1024, proxd_upd_template, my_hostname, proxd_app, proxd_level, smsg, lmsg);
   nb = strlen(buf);
   if (sendto(proxd_sock,buf,nb,0,(struct sockaddr *)&proxd_addr,sizeof(proxd_addr)) != nb) {
      syslog(LOG_ERR, "sending proxd message: %m");
      if (nproxderr++ > 10) {
         syslog(LOG_ERR, "shutting down proxd messaging");
         proxd_sock = 0;
      }
      return (0);
   }
   return (1);
}






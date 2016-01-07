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

/* preauth ADS interface */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>

#undef LDAP_DEBUG

#include "preauth.h"

static char *ads_attributes[] = {
  "uwNetID",
  NULL
};

/* report an ldap error to syslog */
static void report_error(int err, char *msg) {
   char *emsg = ldap_err2string(err);
   syslog(LOG_ERR, "ldap %s: %s", msg, emsg);
   proxd_alert(msg, emsg);
}

/* Get a value for a simgle-valued attribute (assumed) */

static char *get_attr_value(LDAP *ld, LDAPMessage *m, char *attr)
{
   char **vals;
   char *val = NULL;
   if (vals = ldap_get_values(ld, m, attr)) {
      // syslog(LOG_DEBUG, "ldap val %s: %s\n", attr, vals[0] );
      val = strdup(vals[0]);
      ldap_value_free( vals );
   }
   return (val);
}


/* See if the id has the subscription
   Return 1 if Yes; 0 if No; -1 if system failure */


int ads_has_subscription(Env E, char *sub, char *id)
{
   LDAP *ld = E->ldap;
   LDAPMessage    *result, *e;
   char  *regid = NULL;
   int i;
   int nv = 0;
   char filter[2048];
   char *dn = NULL;
   int rc;
   int try;
   int ret = 0;

   /* Look for the account record */

   snprintf(filter, 2048, "(&(uwNetID=%s)(uwActiveSubscription=%s))", id, sub);

   // syslog(LOG_DEBUG, "search: \"%s\"\n", filter);
   // long delays can disconnect us
   for (try=0; try<2; try++) {
      if (!(ld||(ld=ads_init(E)))) {
          syslog(LOG_ERR, "no ldap, cannot verify!");
          return (-1);
      }
      if ((rc=ldap_search_s(ld, E->ads_base, LDAP_SCOPE_SUBTREE,
          filter, ads_attributes, 0, &result )) != LDAP_SUCCESS ) {
               if (try>0) report_error(rc, "ldap_search_s" );
               ldap_msgfree( result );
               ld = NULL; 
               continue;
      }
      break;  // success
   }
   if (try==2) {
      syslog(LOG_ERR, "no ldap, cannot verify!");
      return (-1);
   }

   if (ldap_count_entries(ld, result)>0) {
      // this is not necessary
      e = ldap_first_entry( ld, result );
      char *nid = get_attr_value(ld, e, "uwNetID");
      syslog(LOG_DEBUG, "found: \"%s\"\n", nid);
      free(nid);
      ret = 1;
   } else { 
      syslog(LOG_DEBUG, "not found");
   }
   ldap_msgfree( result );
   return (ret);
}




/* ----- connect and disconnect -------------------------- */



#ifdef LDAP_DEBUG
static void set_ldap_debug()
{
    if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &tegea_debug )
          != LBER_OPT_SUCCESS ) {
      fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", tegea_debug );
    }
    if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &tegea_debug )
         != LDAP_OPT_SUCCESS ) {
      fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", tegea_debug );
    }
}
#endif



/* Callback from the sasl bind */

static int tsasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in)
{
    sasl_interact_t *interact = in;
    /* Should loop through, ++interact, for full SASL stuff. */
    if (interact->id != SASL_CB_LIST_END) {
        interact->result = (char *) interact->defresult;
        if (interact->defresult)
            interact->len = strlen(interact->defresult);
        else
            interact->len = 0;
    }
    return LDAP_SUCCESS;
}


static int set_int_option(LDAP *ld, int option, int iv)
{  
   int rc;
   
   if ( (rc=ldap_set_option( NULL, option, &iv )) != LDAP_SUCCESS ) {
        report_error(rc, "set int opt");
        return (0);
   }
   return (1);
}

static int set_char_option(LDAP *ld, int option, char *cv)
{  
   int rc;
   
   if ( (rc=ldap_set_option( NULL, option, cv )) != LDAP_SUCCESS ) {
        report_error(rc, "set char opt");
        return (0);
   }
   return (1);
}



/* Initialize the library.
   Connects to ldap and authenticates.
   Returns the LDAP pointer
   Returns null on failure
 */

LDAP *ads_init(Env E)
{
    LDAP  *ld = NULL;
    LDAPMessage    *result, *e;
    int        i;
    int h, nh;
    int rc;
    char uri[1024];
   
    syslog(LOG_DEBUG, ".. auth_initialize, host=%s\n", E->ads_host);

    /* Get a handle to the server */

       if (E->ads_ca) {  /* tls version */

#ifdef LDAP_DEBUG
          set_ldap_debug();
#endif

          if (!set_int_option(NULL, LDAP_OPT_PROTOCOL_VERSION, LDAP_VERSION3)) rc=1;
          if (!set_int_option(NULL, LDAP_OPT_X_TLS, LDAP_OPT_X_TLS_DEMAND)) rc=1;
          if (!set_char_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, E->ads_ca)) rc=1;

          sprintf(uri,"ldap://%s:%s/", E->ads_host, E->ads_port);
          if ( (rc = ldap_initialize(&ld,  uri )) != LDAP_SUCCESS ) {
             report_error(rc, "ldap_initialize");
             rc=1;
          }

          syslog(LOG_DEBUG, ".. ldap tls initialize ok\n");

       } else { /* not tls */

          if ( (ld = ldap_init( E->ads_host, atoi(E->ads_port) )) == NULL ) {
             syslog(LOG_ERR,  "non tls ldap_init failed" );
             rc=1;
          }

       } 

       /* Bind */

       if (E->ads_ca && E->ads_crt) {
        
          /* cert */
          syslog(LOG_DEBUG, "using cert from %s\n", E->ads_crt);
          if (!set_char_option(NULL, LDAP_OPT_X_TLS_CERTFILE, E->ads_crt)) exit (1);
          if (!set_char_option(NULL, LDAP_OPT_X_TLS_KEYFILE, E->ads_key)) exit (1);

          if ((rc=ldap_start_tls_s(ld, NULL, NULL)) != LDAP_SUCCESS) {
             report_error(rc, "ldap_start_tls_s");
             rc=1;
          }

          if ((rc=ldap_sasl_interactive_bind_s(ld, NULL, "EXTERNAL", 0, 0,
                LDAP_SASL_AUTOMATIC|LDAP_SASL_QUIET, tsasl_interact, 0)) != LDAP_SUCCESS) {
             report_error(rc, "ldap_sasl_interactive_bind_s");
             rc=1;
          }


       } else {

          syslog(LOG_ERR, "invalid ldap config\n");
          rc=1;
       }
       syslog(LOG_DEBUG, ".. ldap bind ok\n");

       set_int_option( ld, LDAP_OPT_PROTOCOL_VERSION, LDAP_VERSION3);
     

    if (ld) syslog(LOG_DEBUG, ".. ldap connect OK.\n");
    else syslog(LOG_DEBUG, ".. ldap connect failed.\n");
    E->ldap = ld;
    // show_cfg(cfg);
    return (ld);
}



/* Disconnect from the ldap server.  */

void ads_disconnect(Env E)
{
    ldap_unbind( E->ldap );
    E->ldap = NULL;
}


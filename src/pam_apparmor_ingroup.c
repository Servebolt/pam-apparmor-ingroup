#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/apparmor.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

struct options_t {
  int debug;
  int silent;
  char *ingroup;
  char *hat;
};
typedef struct options_t options_t;

static void
parse_option (const pam_handle_t *pamh, const char *argv, options_t *options)
{
	if (argv == NULL || argv[0] == '\0')
		return;
	if (strcasecmp (argv, "debug") == 0)
		options->debug = 1;
	else if (strncasecmp (argv, "ingroup=", 8) == 0)
		options->ingroup = strdup (&argv[8]);
	else if (strncasecmp (argv, "hat=", 4) == 0)
		options->hat = strdup (&argv[4]);
	else
		pam_syslog (pamh, LOG_ERR, "Unknown option: `%s'", argv);
}

static int
get_options (const pam_handle_t *pamh, options_t *options,
             int argc, const char **argv)
{
	memset (options, 0, sizeof (options_t));
	/* Parse parameters for module */
	for ( ; argc-- > 0; argv++)
		parse_option (pamh, *argv, options);

	if (options->ingroup == NULL)
		options->ingroup = "confined";

	if (options->hat == NULL)
		options->hat = "confined";

	return 0;
}

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc, const char **argv)
{
	options_t options;
	const char *user = NULL;
	const char *hat = "unconfined";
    char *con, *new_con;
	int pam_retval = PAM_SUCCESS;
	int retval;
    int aa_avail = 1;

	get_options(pamh, &options, argc, argv);
	if (flags & PAM_SILENT)
		options.silent = 1;

	/* Resolve user and search groups */
	retval = pam_get_user(pamh, &user, NULL);
	if ( retval != PAM_SUCCESS ) {
		D(("get user returned error: %s", pam_strerror(pamh,retval)));
		return retval;
	}

	if (user == NULL || *user == '\0')
		return PAM_USER_UNKNOWN;

    if ( aa_getcon(&con, NULL) == -1 ) {
        pam_syslog(pamh, LOG_ERR, "Failed to query apparmor confinement. Please check if \"/proc/*/attr/current\" is read and writeable.\n");
        aa_avail = 0;
    }

    if ( pam_modutil_user_in_group_nam_nam(pamh, user, options.ingroup) == 0 ) {
        /* dont break everything if the user isnt confined anyway */
        if ( aa_avail == 0 )
            return PAM_SUCCESS;
        pam_syslog(pamh, LOG_DEBUG, "Not in confinement group, using \"%s\"\n", hat);
    }
    else {
        hat = options.hat;
        pam_syslog(pamh, LOG_DEBUG, "User is confined, using \"%s\"\n", hat);
    }

    if ( aa_avail == 0 ) {
        pam_syslog(pamh, LOG_ERR, "Apparmor is not available\n");
        return PAM_SESSION_ERR;
    }

    new_con = malloc(strlen(con) + strlen(hat) + 3); // // + 0 Byte
    if ( !new_con ) {
        pam_syslog(pamh, LOG_ERR, "failed to allocate memory\n");
        return PAM_SYSTEM_ERR;
    }

    if ( 0 > sprintf(new_con, "%s//%s", con, hat) ) {
        pam_syslog(pamh, LOG_ERR, "failed to construct full profile name\n");
        pam_retval = PAM_SESSION_ERR;
        goto out;
    }

    if ( 0 > aa_change_profile(new_con) ) {
        pam_syslog(pamh, LOG_ERR, "failed to change to new confinement \"%s\". Check that \"change_profile -> %s//*\" is allowed.\n", new_con, con);
        pam_retval = PAM_SESSION_ERR;
        goto out;
    }

	out:
        free(con);
        free(new_con);
        return pam_retval;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc,
                         const char **argv)
{
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_apparmor_ingroup_modstruct = {
	"pam_apparmor_ingroup",
	NULL,
	NULL,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL
};

#endif

/* end of module definition */

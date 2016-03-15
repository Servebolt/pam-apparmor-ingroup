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

	return 0;
}

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc, const char **argv)
{
	options_t options;
	const char *user = NULL;
	const char *subprofile = "confined"; // default to confined
	const char *unconfined = "unconfined";
	char *con, *new_con;
	int retval, pam_retval = PAM_SUCCESS, aa_avail = 1;

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
		pam_syslog(pamh, LOG_ERR, "failed to query apparmor confinement. Please check if \"/proc/*/attr/current\" is read and writeable.\n");
		aa_avail = 0;
	}

	if ( strncmp(con, "unconfined", 10) == 0 ) {
		pam_syslog(pamh, LOG_ERR, "process is not running under an apparmor profile.\n");
		aa_avail = 0;
	}

	if ( pam_modutil_user_in_group_nam_nam(pamh, user, options.ingroup) == 0 ) {
		/* dont break everything if the user isnt confined anyway */
		if ( aa_avail == 0 )
			return PAM_SUCCESS;
		subprofile = unconfined;
		pam_syslog(pamh, LOG_DEBUG, "not in confinement group\n");
	}
	else {
		pam_syslog(pamh, LOG_DEBUG, "user wants to be confined\n");
	}

	if ( aa_avail == 0 ) {
		pam_syslog(pamh, LOG_ERR, "AppArmor is not available\n");
		return PAM_SESSION_ERR;
	}

	new_con = malloc(strlen(con) + strlen(subprofile) + 3); // // + 0 Byte
	if ( !new_con ) {
		pam_syslog(pamh, LOG_ERR, "failed to allocate memory\n");
		return PAM_SYSTEM_ERR;
	}

	if ( 0 > sprintf(new_con, "%s//%s", con, subprofile) ) {
		pam_syslog(pamh, LOG_ERR, "failed to construct full profile name\n");
		pam_retval = PAM_SESSION_ERR;
		goto out;
	}

	pam_syslog(pamh, LOG_DEBUG, "transitioning to profile name \"%s\"\n", new_con);

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

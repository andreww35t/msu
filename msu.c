/*
 * $Id: msu.c,v 1.13 2006/08/11 11:28:44 abs Exp $
 *
 * msu: (c) 1996,1999,2002 DKBrownlee (abs@mono.org). May be freely distributed.
 * Provides passwordless access to given accounts from a list of other accounts
 * No warranty, implied or otherwise. Stick no bills. Suggestions welcome.
 *
 *	Format of a line in msu.conf file is:
 * 		destination_account:path_to_shell:account1,account2,account3
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define VERSION		"1.09"

#ifndef CONFIG_FILE
#define CONFIG_FILE      "/usr/local/etc/msu.conf"
#endif

extern char **environ;

void become(const char *to, const char *shell, const char *from);
void log_msu(int no_return, const char *from, const char *to, const char *text);
void stripenv(char **envp);

int main(int argc, char **argv)
    {
    struct      passwd  *pwd;
    FILE        *fds;
    char	*to = 0,
		*from,
	        readline[1024],
		*account,
		*shell,
		*ptr;

    if ((pwd = getpwuid(getuid())) == 0 || pwd->pw_name == 0)
	{
	fputs("Unable to determine your account\n", stderr);
	exit(3);
	}
    from = strdup(pwd->pw_name);
    if (!from)
	errx(1, "Malloc of '%s' failed", pwd->pw_name);

    if (argc > 1)
	to = argv[1];

    if ((fds = fopen(CONFIG_FILE, "r")) == 0)
	err(1, "Unable to open config file '" CONFIG_FILE "'");
    while (fgets(readline, (int)sizeof(readline), fds))
	{
	if (!(ptr = strchr(readline, '\n')))
	    err(1, CONFIG_FILE ": Missing newline - line too long?");
	if ((ptr = strchr(readline, '#')))
	    *ptr = 0;
	if ((account = strtok(readline, ":")) && (shell = strtok(0, ":")))
	    {
	    if (to)
		{
		if (strcmp(account, to) == 0)
		    {
		    while( (ptr = strtok(0, ",\n")) )
			if (strcmp(ptr, from) == 0 || getuid() == 0)
			    {
			    (void)fclose(fds);
			    become(account, shell, from);
			    }
		    log_msu(1, from, to, "*** Invalid authorisation");
		    }
		}
	    else
		while ((ptr = strtok(0, ",\n")))
		    if (strcmp(ptr, from) == 0)
			{
			(void)fclose(fds);
			become(account, shell, from);
			}
	    }
	}
    (void)fclose(fds);
    log_msu(1, from, to, to?"* No such account":"* No valid accounts");
    return(1);
    }

void become(const char *to, const char *shell, const char *from)
    {
    struct	stat	tmpstat;
    struct      passwd  *destpwd;
    const char	*ptr;
    char	*shell_argv0;

    if ((destpwd = getpwnam(to)) == 0 || destpwd->pw_uid == 0)
	log_msu(1, from, to, "* Invalid account");
    log_msu(0, from, to, "Ok");

    /* Ensure the destination user owns the tty - for screen etc */
    if (isatty(0))
	fchown(0, destpwd->pw_uid, (gid_t)-1);

    if (setgid(destpwd->pw_gid))
	err(1, "Unable to setgid(%d)", destpwd->pw_gid);
    if (setuid(destpwd->pw_uid))
	err(1, "Unable to setuid(%d)", destpwd->pw_uid);

    if (destpwd->pw_dir)
	{
	if (stat(".", &tmpstat) || tmpstat.st_uid != destpwd->pw_uid)
	    chdir(destpwd->pw_dir);
	setenv("HOME", destpwd->pw_dir, 1);
	}
    if ((ptr = getenv("USER")))
	setenv("OLD_USER", ptr, 1);
    setenv("USER", to, 1);

    /* Setup argv to contain shell basename prefixed by '-'  - 'login' shell */
    if ((ptr = strrchr(shell, '/')))
	++ptr;
    else
	ptr = shell;
    if (!(shell_argv0 = malloc(strlen(ptr)+2)))
	errx(1, "* Malloc '%s' failed", ptr);
    strcpy(shell_argv0+1, ptr);
    shell_argv0[0] = '-';

    stripenv(environ);
    setenv("SHELL", shell, 1);
    execl(shell, shell_argv0, 0);
    exit(3);
    }

void log_msu(int no_return, const char *from, const char *to, const char *text)
    {
    if (to == 0)
	{
	fprintf(stderr, "%s\n", text);
	syslog(no_return ?LOG_WARNING :LOG_INFO, "msu %s - %s", from, text);
	}
    else
	{
	fprintf(stderr, "%s \"%s\"\n", text, to);
	syslog(no_return ?LOG_WARNING :LOG_INFO, "msu %s to %s - %s", from, to,
								    text);
	}
    if (no_return)
        exit(3);
    }

/* stripenv taken from edelkind-bugtraq@episec.com */
void stripenv(char **envp)
    {
    char **p1, **p2;

    /* the following entries are based on Lawrence R. Rogers'
     * wrapper in cert advisory CA-1995-14 */
    for (p1 = p2 = envp; *p1; p1++)
	{
	if (memcmp(*p1, "LD_", 3) == 0 || memcmp(*p1, "LIBPATH=", 8) == 0 ||
		memcmp(*p1, "ELF_LD_", 7) == 0 || memcmp(*p1, "_RLD", 4) == 0 ||
		memcmp(*p1, "AOUT_LD_", 8) == 0 || memcmp(*p1, "IFS=", 4) == 0)
	    continue;
	*p2++ = *p1;
	}
    *p2 = 0;
    }

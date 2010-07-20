/*

   pam_encfs by Anders Aagaard <aagaande@gmail.com>

   ############################################################################
   #    Copyright (C) 2004 by Anders Aagaard                                          
   #    aagaande@gmail.com                                             
   #                                                                          
   #    This program is free software; you can redistribute it and#or modify  
   #    it under the terms of the GNU General Public License as published by  
   #    the Free Software Foundation; either version 2 of the License, or     
   #    (at your option) any later version.                                   
   #                                                                          
   #    This program is distributed in the hope that it will be useful,       
   #    but WITHOUT ANY WARRANTY; without even the implied warranty of        
   #    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         
   #    GNU General Public License for more details.                          
   #                                                                          
   #    You should have received a copy of the GNU General Public License     
   #    along with this program; if not, write to the                         
   #    Free Software Foundation, Inc.,                                       
   #    59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             
   ############################################################################ */

  /*
     Todo:
     - Cleanup
     - check if paths from pam_encfs.conf has trailing slash and remove it.
     - support changing passwords (hm.. do we want to do that?  Screwing up mount/umount is ok, screwing up changing password is not.)
     - option to let this count as "main" authentication, ie send OK back instead of ignore.
     - atm I send ignore to avoid any potentional security problems.
     - also not sure if I wanna support this, as it wouldn't work every time the directory is already mounted.
   */



#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* for solaris compatibility */
#define _POSIX_PTHREAD_SEMANTICS

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MISC_H
#include <security/pam_misc.h>
#elif defined(HAVE_PAM_PAM_MISC_H)
#include <pam/pam_misc.h>
#endif

#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#else
#include <pam/pam_modules.h>
#endif

#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <sys/ioctl.h>
#include <fcntl.h>
#include <mntent.h>
#include <wait.h>


#define READ_END 0
#define WRITE_END 1
#define USERNAME_MAX    127
#define PATH_MAX    256
#define BUFSIZE ((USERNAME_MAX +1) + ((PATH_MAX+1) * 2))
#define CONFIGFILE     "/etc/security/pam_encfs.conf"

static void _pam_log(int err, const char *format, ...);
static char default_encfs_options[USERNAME_MAX];
static char default_fuse_options[USERNAME_MAX];
static int drop_permissions = 0;

/* --------------------------- PAM functions -------------------------------- */

/* this function ripped from pam_unix/support.c */
int converse(pam_handle_t * pamh,
             int nargs,
             struct pam_message **message, struct pam_response **response)
{
    int retval;
    struct pam_conv *conv;

    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (retval == PAM_SUCCESS)
    {
        retval = conv->conv(nargs,
                            (const struct pam_message **) message,
                            response, conv->appdata_ptr);
    }
    return retval;
}





/* this function ripped from pam_unix/support.c */
int _set_auth_tok(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
    int retval;
    char *p;

    struct pam_message msg[1], *pmsg[1];
    struct pam_response *resp;

    /* set up conversation call */

    pmsg[0] = &msg[0];
    msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
    msg[0].msg = "Password: ";
    resp = NULL;

    if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
        return retval;

    if (resp)
    {
        if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL)
        {
            free(resp);
            return PAM_AUTH_ERR;
        }

        p = resp[0].resp;

        /* This could be a memory leak. If resp[0].resp 
           is malloc()ed, then it has to be free()ed! 
           -- alex 
         */

        resp[0].resp = NULL;

    }
    else
        return PAM_CONV_ERR;

    free(resp);
    pam_set_item(pamh, PAM_AUTHTOK, p);
    return PAM_SUCCESS;
}

int waitpid_timeout(pid_t pid, int *status, int options)
{
    pid_t retval;
    int i = 0;

    do
    {
        retval = waitpid(pid, status, options);
        if (i++ > 10)
        {
            return 1;
        }
    }
    while (retval == 0 || (retval == -1 && errno == EINTR));
    return 0;
}

int is_dir(const char *path)
{
    struct stat statbuf;
    if ((stat(path,&statbuf) == 0) && (S_ISDIR(statbuf.st_mode) == 1)) {
        return 1;
    }
    return 0;
}

int checkmnt(const char *targetpath)
{
    FILE *f = setmntent("/etc/mtab", "r");
    struct mntent *m;

    while ((m = getmntent(f)))
    {
        if (strcmp(m->mnt_fsname, "encfs") == 0)
        {
            // DEBUG _pam_log(LOG_ERR, "Found mounted fuse system : %s",m->mnt_dir);
            if (strcmp(targetpath, m->mnt_dir) == 0)
            {
                // DEBUG _pam_log(LOG_ERR, "ENCFS already mounted on : %s",m->mnt_dir);
                return 1;
            }
        }
    }
    return 0;
}

void searchAndReplace(char *line)
{
    char *str;

    do
    {
        str = strchr(line, ',');
        if (str != NULL)
        {
            *str = ' ';
        }
    }
    while (str != NULL);
}

int buildCmd(char *arg[], int pos, char *line)
{
    int orig_pos = pos;

    if (strlen(line) == 0)
        return 0;
    while (line)
    {
        arg[pos++] = line;
        if ((line = strchr(line, ' ')))
        {
            *line++ = '\0';
        }
    }
    return pos - orig_pos;
}


const char *getHome(struct passwd *pwd, pam_handle_t * pamh)
{
    const char *tmp = NULL;

    tmp = pam_getenv(pamh, "HOME");
    
    if (!tmp || *tmp == '\0')
    {
        if (pwd->pw_dir && pwd->pw_dir != '\0')
            return pwd->pw_dir;
        else
            return NULL;
    }
    else
        return tmp;
}

int readconfig(struct passwd *pwd, pam_handle_t * pamh, const char *user,
               char *path, char *targetpath, char *encfs_options,
               char *fuse_options)
{
    FILE *conffile;
    char line[BUFSIZE];
    char username[USERNAME_MAX];
    int parsed;
    const char *tmp;

    // Return 1 = error, 2 = silent error (ie already mounted)

    if ((conffile = fopen(CONFIGFILE, "r")) == NULL)
    {
        _pam_log(LOG_ERR, "Failed to open conffile %s", CONFIGFILE);
        return 0;
    }

    while (fgets(line, BUFSIZE, conffile) != NULL)
    {
        if (line[0] == '#')
            continue;
        parsed =
            sscanf(line, "%s%s%s%s%s", username, path, targetpath,
                   encfs_options, fuse_options);
        if (parsed == -1)
            continue;
        if (strcmp("drop_permissions", username) == 0)
        {
            drop_permissions = 1;
            continue;
        }
        if (strcmp("encfs_default", username) == 0)
        {
            if (parsed == 2 && !strcmp("-",path) == 0)
                strcpy(default_encfs_options, path);
            continue;
        }
        if (strcmp("fuse_default", username) == 0)
        {
            if (parsed == 2 && !strcmp("-",path) == 0)
                strcpy(default_fuse_options, path);
            continue;
        }

        if (parsed == 5)
        {
            // Parsing user:
            if (strcmp("-", encfs_options) == 0)
                strcpy(encfs_options, "");
            if (strcmp("-", fuse_options) == 0)
                strcpy(fuse_options, "");

            searchAndReplace(default_encfs_options);
            searchAndReplace(encfs_options);
            
            // Check if this is the right user / default user.
            if ((strcmp("-",username) != 0) && (strcmp(user,username) != 0)
                && (strcmp("*",username) !=0))
              continue;
            
            
            if (strcmp("-",username) == 0) {
              strcat(path, "/");
                strcat(path, user);
                // Todo check if dir exists and give better error msg.
            }
            
            // If username is '*', paths are relative to $HOME
            if (strcmp("*", username) == 0
                && strcmp("-", targetpath) != 0)
            {
                if ((tmp = getHome(pwd, pamh)))
                {
                        char home[PATH_MAX];

                        strcpy(home, tmp);
                        strcat(home, "/");
                        strcat(home, path);
                        strcpy(path, home);

                        strcpy(home, tmp);
                        strcat(home, "/");
                        strcat(home, targetpath);
                        strcpy(targetpath, home);
                }
            }
            
            if (strcmp("-", targetpath) == 0)
            {
                // We do not have targetpath, construct one.
                strcpy(targetpath, "");

                if ((tmp = getHome(pwd, pamh)))
                {
                    strcpy(targetpath, tmp);
                }
            }



            // Done, check targetpath and return.

            if (!targetpath || *targetpath == '\0')
            {
                _pam_log(LOG_ERR, "Can't get to HOME dir for user %s", user);
                fclose(conffile);
                return 0;
            }

            // Check if path exists, if we're "-" then we dont care, if not we give error.
            if (is_dir(path))
            {
                // We may fail to stat this directory (EPERM) if it's mounted because of fuse's funky permission system.
                if (!is_dir(targetpath))
                {
                    if (checkmnt(targetpath))
                    {
                        // Doublecheck if we're mounted, for some reason we can't stat the dir even when root if it's mounted.
                        // we are mounted, but we return 1 anyway so we can store targetpath
                        fclose(conffile);
                        return 1;
                    }
                    _pam_log(LOG_ERR, "TargetPath for %s does not exist (%s)",
                             user, targetpath);
                    fclose(conffile);
                    return 0;
                }
                fclose(conffile);
                return 1;
            }

            // Path does not exist, if we're a specified user give error, if not keep looking.

            if ((strcmp("-", username) != 0)
              && (strcmp("*", username) != 0))
            {
                _pam_log(LOG_ERR, "Path for %s does not exist (%s)", user,
                         path);
                fclose(conffile);
                return 0;
            }
            continue;

        }

        continue;
    }


    fclose(conffile);
    return 0;
}

static void targetpath_cleanup(pam_handle_t * pamh, void *ptr, int err)
{
    if (ptr)
        free(ptr);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh,
                                   int flags, int argc, const char **argv)
{

    const char *user = NULL, *passwd = NULL;
    struct passwd *pwd;
    int rval, status;
    pid_t pid;


    // For checking mount paths: (mount from + target)
    char path[PATH_MAX];
    char targetpath[PATH_MAX];
    char encfs_options[USERNAME_MAX];
    char fuse_options[USERNAME_MAX];
    char *targetpath_store;

    strcpy(default_encfs_options, "");
    strcpy(default_fuse_options, "");

    // For execing:
    char *arg[USERNAME_MAX];
    int arg_pos = 0;
    int i;
    int inpipe[2], outpipe[2];

    rval = pam_get_user(pamh, &user, NULL);
    if ((rval != PAM_SUCCESS) || (!user))
    {
        _pam_log(LOG_ERR, "can't get username: %s", pam_strerror(pamh, rval));
        return PAM_AUTH_ERR;
    }

    rval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) (void *) &passwd);
    if (rval != PAM_SUCCESS)
    {
        _pam_log(LOG_ERR, "Could not retrieve user's password");
        return PAM_AUTH_ERR;
    }

    if (!passwd)
    {
        rval = _set_auth_tok(pamh, flags, argc, argv);
        if (rval != PAM_SUCCESS)
        {
            return rval;
        }
        rval =
            pam_get_item(pamh, PAM_AUTHTOK, (const void **) (void *) &passwd);
        if (rval != PAM_SUCCESS || passwd == NULL)
        {
            _pam_log(LOG_ERR, "Could not retrieve user's password");
            return PAM_AUTH_ERR;
        }
    }
    if ((pwd = getpwnam(user)) == NULL)
    {
        _pam_log(LOG_ERR, "Could not getpwnam");
        return PAM_AUTH_ERR;
    }

    // Read configfile  
    if (!readconfig
        (pwd, pamh, pwd->pw_name, path, targetpath, encfs_options,
         fuse_options))
    {
        // DEBUG _pam_log(LOG_ERR,"No entry for user found in log");
        return PAM_IGNORE;
    }
    //DEBUG _pam_log(LOG_ERR,"Username : %s, Encpath : %s, Targetmount : %s",pwd->pw_name,path,targetpath);

    //Store targetpath
    targetpath_store = strdup(targetpath);
    if ((i =
         pam_set_data(pamh, "encfs_targetpath", targetpath_store,
                      targetpath_cleanup)) != PAM_SUCCESS)
    {
        _pam_log(LOG_ERR, "Storing targetpath FAIL");
        free(targetpath_store);
        return i;
    }

    // Check if we're mounted already.
    if (checkmnt(targetpath))
    {
        //DEBUG _pam_log(LOG_ERR,"Already mounted");
        return PAM_IGNORE;
    }



    /*  _pam_log(LOG_ERR,"Config output for %s:",user);
       _pam_log(LOG_ERR,"  path       : %s",path);
       _pam_log(LOG_ERR,"  targetpath : %s",targetpath);
       _pam_log(LOG_ERR,"  encfs      : %s %s",default_encfs_options,encfs_options);
       _pam_log(LOG_ERR,"  fuse       : %s %s",default_fuse_options,fuse_options); */


    arg_pos += buildCmd(arg, arg_pos, "encfs");
    arg_pos += buildCmd(arg, arg_pos, "-S");
    arg_pos += buildCmd(arg, arg_pos, default_encfs_options);
    arg_pos += buildCmd(arg, arg_pos, encfs_options);
    arg_pos += buildCmd(arg, arg_pos, path);
    arg_pos += buildCmd(arg, arg_pos, targetpath);

    if (strlen(default_fuse_options) > 0 && strlen(fuse_options) > 0)
        strcat(fuse_options, ",");

    strcat(fuse_options,default_fuse_options);
    if (strlen(fuse_options) > 0) {
        arg_pos += buildCmd(arg, arg_pos, "--");
        arg_pos += buildCmd(arg, arg_pos, "-o");
        arg_pos += buildCmd(arg, arg_pos, fuse_options);
    }
    arg[arg_pos] = NULL;

    /*  printf("Arguments : ");
       for (i = 0; i < arg_pos+1;i++) {
       _pam_log(LOG_ERR,"Data : %s",arg[i]);
       }

       _pam_log(LOG_ERR,"Number of arguments : %d",arg_pos); */


    /*  arg[0] = cmd;
       arg[1] = params;
       //  arg[2] = params2;
       arg[2] = params3;
       arg[3] = path;
       arg[4] = targetpath;
       arg[5] = fuseparams;
       arg[6] = fuseparams2;
       arg[7] = NULL; */



    if (pipe(inpipe) || pipe(outpipe))
    {
        _pam_log(LOG_ERR, "Failed to create pipe");
        return PAM_IGNORE;
    }

    // Execute 
    switch (pid = fork())
    {
        case -1:
            _pam_log(LOG_ERR, "Fork failed");
            return PAM_SERVICE_ERR;
        case 0:

            if (drop_permissions == 1)
                if ((initgroups(pwd->pw_name, pwd->pw_gid) == -1)
                    || (setgid(pwd->pw_gid) == -1)
                    || (setuid(pwd->pw_uid) == -1))
                {
                    _pam_log(LOG_ERR, "Dropping permissions failed");
                    return PAM_SERVICE_ERR;
                }
            close(outpipe[WRITE_END]);
            dup2(outpipe[READ_END], fileno(stdin));
            close(outpipe[READ_END]);

            close(inpipe[READ_END]);
            dup2(inpipe[WRITE_END], fileno(stdout));
            close(inpipe[WRITE_END]);

            // For some reason the current directory has to be set to targetpath (or path?) before exec'ing encfs through gdm
            chdir(targetpath);
            execvp("encfs", arg);
            char errstr[128];

            snprintf(errstr, 127, "%d - %s", errno, strerror(errno));
            _pam_log(LOG_ERR, "Exec failed - %s", errstr);
            exit(127);
    }

    int len;


    close(inpipe[WRITE_END]);
    close(outpipe[READ_END]);




    if (waitpid(pid, &status, WNOHANG) == 0)
    {
        len = write(outpipe[WRITE_END], passwd, (size_t) strlen(passwd));
        if ((len != (size_t) strlen(passwd))
            || (write(outpipe[WRITE_END], "\n", 1) != 1))
            _pam_log(LOG_ERR, "Did not send password to pipe (%d sent)", len);
        close(outpipe[WRITE_END]);
    }


    if (waitpid_timeout(pid, &status, 0))
    {
        _pam_log(LOG_ERR, "Timed out waiting for encfs, killing\n");
        kill(pid, SIGKILL);
    }

    int exitstatus = WEXITSTATUS(status);
    char buff[512];

    len = read(inpipe[READ_END], &buff, 511);
    close(inpipe[READ_END]);
    buff[len] = 0;
    if (!checkmnt(targetpath) && (len > 0 || exitstatus > 0))
    {
        _pam_log(LOG_ERR, "exitcode : %d, errorstring : %s", exitstatus,
                 buff);
        return PAM_AUTH_ERR;
    }
    else
    {
        return PAM_IGNORE;
    }
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh,
                                int flags, int argc, const char *argv[])
{
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh,
                                int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh,
                                   int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh,
                                    int flags, int argc, const char **argv)
{

    int retval;
    pid_t pid;
    char *targetpath;
    char *args[4];

    //  _pam_log(LOG_ERR,"Geteuid : %d",geteuid());

    if ((retval =
         pam_get_data(pamh, "encfs_targetpath",
                      (const void **) &targetpath)) != PAM_SUCCESS)
        return retval;

    if (!checkmnt(targetpath))
    {
        _pam_log(LOG_ERR, "Targetpath is not mounted!: %s", targetpath);
        return PAM_SERVICE_ERR;
    }

    args[0] = "fusermount";
    args[1] = "-uz";
    args[2] = targetpath;
    args[3] = NULL;

    switch (pid = fork())
    {
        case -1:
            _pam_log(LOG_ERR, "Fork failed");
            return PAM_SERVICE_ERR;
        case 0:
            execvp("fusermount", args);
            char errstr[128];

            snprintf(errstr, 127, "%d - %s", errno, strerror(errno));
            _pam_log(LOG_ERR, "Exec failed - %s", errstr);
            exit(127);
    }

    if (waitpid(pid, NULL, 0) == -1)
      _pam_log(LOG_ERR, "Waitpid failed - %s", strerror(errno));

    /*We'll get this error every single time we have more than one session active, todo fix this with some better checks + support fuser -km if no more session connected.  
       if (checkmnt(targetpath)) {
       _pam_log(LOG_ERR,"Failed to unmount %s",targetpath);
       return PAM_SERVICE_ERR;
       } */

    return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh,
                              int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

/* function for correct syslog logging 
   provided by Scipio <scipio@freemail.hu> */
static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog("pam_encfs", LOG_CONS | LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

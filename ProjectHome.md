pam\_encfs is a module to auto mount encfs dir on login.

See [Readme from svn](http://pam-encfs.googlecode.com/svn/trunk/README) for more information.

An example configuration file is available [here](http://pam-encfs.googlecode.com/svn/trunk/pam_encfs.conf).

Note that the lack of activity means it's stable, I've been using it for ages without any problems whatsoever.

**Note, this is no longer actively maintained, but has been stable for a long time.**

**Note, version 0.1.3 and newer has flag "nonempty" on per default, this argument requires fuse 2.4 or newer.**

**News**:

**Release 0.1.4.4 - July 20 2010.**
  * Use fuse lazy umount by default.

**Release 0.1.4.3 - May 16 2010.**
  * Applied patch from Francesco Sacchi to allow auto mounting subdirectories (like .private) with wildcards.

**Release 0.1.4.2 - Apr 21 2008.**
  * Applied 2 patches from the debian package. (Thanks Rubèn Porras for mailing em to me).
  * Removed -x from the Makefile, god knows why that was there in the first place.

**Release 0.1.4.1 - Jul 28 2006.**
  * Applied a patch from Yves Perrenoud fixing an odd bug in gdm logins introduced in 0.1.4.

**Release 0.1.4 - Jul 27 2006.**
  * Fixed a bug related to sudo and chdir (not a security issue), now using stat instead, thanks to Yves Perrenoud for the bugreport + suggested fix.

**Release 0.1.3 - Dec 1 2005.**
  * Fixed a few misc bugs, no critical stuff so if you had it working before there's no reason to update.
  * Thanks to Philippe Teuwen for some patches.

**Release 0.1.2**
  * Updates are documentation/contact information.


---

**Latest Release** : http://code.google.com/p/pam-encfs/downloads/list

**Svn Tree** : http://pam-encfs.googlecode.com/svn/trunk/
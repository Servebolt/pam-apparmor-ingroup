# AppArmor PAM module

This is an alternative to the PAM module AppArmor ships, and is loosely based on it. The main differences are that we only use two sub profiles, `unconfined` and `confined`, and select which one to use based on supplementary groups rather than user name or primary group.

This makes it easier to set up confinement of a group of users without having to define hats for every user or using primary groups which are incompatible with usergroups and the like.

### Installation from source

Make sure PAM, AppArmor development files and a working C compiler are installed on your build system.

On Ubuntu, Debian and their derivatives that would be the packages build-essential, libpam0g-dev and libapparmor-dev

    ./configure
    make
    sudo make install

### Arguments

    ingroup=

What group to check for. If found we apply the confined profile.

### Missing
Example profiles and PAM configuration

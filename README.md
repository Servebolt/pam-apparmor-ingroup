# AppArmor PAM module

This is an alternative to the PAM module AppArmor ships, and is loosely based on it. The main differences are that we only use two hats, the DEFAULT and the confined, and select which one to use based on supplementary groups rather than user name or primary group.

### Installation from source

Make sure PAM, AppArmor development files and a working C compiler are installed on your build system.

On Ubuntu, Debian and their derivatives that would be the packages build-essential, libpam0g-dev and libapparmor-dev

    ./configure
    make
    sudo make install

### Arguments

    ingroup=

Group to check for. Default is `confined`

    hat=

What hat to change to if the group is found. Default is `confined`. If the ingroup group is not found the DEFAULT hat is applied. In most cases DEFAULT would set the users shell to escape any confinement.

### Setup

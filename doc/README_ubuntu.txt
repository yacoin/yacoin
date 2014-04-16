This file contains instructions for how to build YACoin for Ubuntu on Ubuntu Server 12.04 using
Oracle VirtualBox. When completed, you will be able to build the static loaded yacoind using the
tested versions of libraries YACoin needs to run properly. A fresh install of Ubuntu Server 12.04 is
used so as to have a consistent build environment UN-tarnished by system changes.

These instructions are targeted for Ubuntu Server 12.04 and Ubuntu Desktop 12.04, but should be 
useful for other Linux flavors as well. A section for CentOS 6.5 has been added to the bottom.

NOTE: The makefile for these instructions is found in src/makefile.ubuntu

Why would you want to build YACoin this way?

      1 - It can be frustrating to build YACoin for the first time. This will work every time.

      2 - Web servers usually have lots of added programs, libraries and configurations. Building
      YACoin this way makes sure your YACoin build is UN-tarnished.

      3 - YACoin must be statically built with specific versions of libraries that are not usually
      included in Ubuntu.

      4 - Having your own Ubuntu build of YACoin is a great way to enable web based YACoin services
      that are built on Ubuntu servers to interact with YACoin.

      5 - A stand alone VirtualBox running Ubuntu server 12.04 is a also a great way to run YACoin
      in a secure environment, where it becomes much harder for anybody to steel your YACoin. This
      might be especially important if you have a large stockpile of YACoin that you like to get
      Proof of Stake (POS) rewards from.

      6 - Developing and debugging YACoin may be easier for those who are more familiar with a Linux
      environment, and developers need to use the correct libraries to be productive.

      7 - People who use Linux love to build stuff from scratch!

NOTE: these instructions were developed using Windows 7 on a 64 bit machine as the VirtualBox host.
Of course any computer that can run VirtualBox can be used.

Section A - Get Ubuntu Server 12.04.3 running inside VirtualBox with OpenSHH Server.

      1 - If you don't already have VirtualBox installed, download and install the latest VirtualBox
      from http://www.virtualbox.org. Click on Downloads and get the binary installer for Windows
      hosts.

      2 - Download Ubuntu Server 12.04.3 LTS 64 bit from http://www.ubuntu.com. Click
      Download->Server at the top. Select 64-bit and click "Get Ubuntu 12.04 LTS".

      3 - Create a virtual machine in VirtualBox. Click New. Give the VM a name, like "yacoin
      builder". Select "Linux" as the type and "Ubuntu (64 bit)" as the version. Click "Next". Give
      the virtual machine at least 1024 MB of memory. Click "Next". Click "Create" to create a new
      virtual hard drive. Click "Next" to use VDI hard drive type. Click "Next" to use Dynamically
      allocated. Click "Create" to create a hard drive with 8.00 GB of space.

      5 - Before firing up the virtual machine, we want to bridge the network interface so that
      we can SSH to it easily. Click on "yacoin builder" and hit the "Settings" button. Click
      on "Network". Change the "Attached to:" to "Bridged Adapter". Click "OK". Then we want to
      load our CD image of Ubuntu Server 12.0.4.3. Still in "Settings", click "Storage". Under
      "Controller: IDE" click "Empty". Then click the picture of a CD to the right and select
      "Choose a virtual CD/DVD disk file...". Navigate and select the downloaded ubuntu image file
      "ubuntu-12.04.3-server-amd64.iso". Click "OK" to get out of "Settings". Click "Start" to fire
      up the virtual machine.

      6 - Click the window that pops up and let the window capture your mouse. You can get your
      mouse back at any time by hitting the right Ctrl key on your keyboard. Hit enter to accept
      English. Hit enter to "Install Ubuntu Server". Hit enter for English again. Use your arrow
      keys to select your country and hit enter. Use the tab key to move the cursor around. Hit
      enter to skip detect keyboard layout. Hit enter to use English keyboard. Hit enter to use
      English keyboard layout. After a few minutes of loading, choose your hostname. Leaving as
      "ubuntu" is OK. Tab, then enter to accept host name. Type a user name (like "yacbuild"). Tab
      and enter to continue. Tab and enter again to use "yacbuild" as account name. Make a password.
      Don't forget the user name and password! Tab and enter to continue. Verify password, tab and
      enter to continue. Hit enter to not encrypt home directory. NOTE: If you intend on using
      this server to store lots of YACoin, you may choose to encrypt your home directory for extra
      security. Hit enter to accept your time zone. Hit enter to select "Guided - use entire disk
      and set up LVM". Hit enter to select select disk to partition. Tab to "Yes" and hit enter to
      "Write changes to disks and configure LVM". Tab and enter to use the whole disk. Tab then
      enter to "Write the changes to disks". After some time, tab and enter to not use a proxy server
      (unless you want to use a proxy server for your Internet connection). After some time, hit
      enter to select "No automatic updates". Hit the space bar to select "OpenSHH server". Tab and
      enter to accept OpenSSH server selection. After some time, hit enter to "Install the GRUB boot
      loader to the mater boot record". Don't worry, that will only effect the virtual machine. After
      some time, hit enter to reboot the virtual machine.

Section B - Updating Ubuntu Server 12.04.3

      1 - Login into the VirtualBox window running Ubuntu Server 12.04.3.

      2 - Type "sudo apt-get update" and enter your password to get the latest security updates.

      3 - Type "sudo apt-get upgrade" to install the latest security updates. Hit enter to accept
      the updates.

      4 - Type "sudo shutdown -P now" to shut down the virtual machine.

      5 - Now is a great time to make a snapshot of your virtual machine in case you want to start
      over from here. In the "Oracle VM VirtualBox Manager" window, click the icon that looks like a
      camera. Give the snapshot a name like "Fresh install with updates".

      6 - Start the virtual machine back up by clicking the green "Start" button.

Section C - Login to your virtual machine using SSH

The VirtualBox window running your virtual machine is small and clunky. We want to use the Putty SSH
client to login to the virtual machine because it is fast, beautiful, and the window can be resized.
Download Putty from http://www.putty.org. Get the putty.exe file for "Windows on Intel x86". It's
just an executable file. There is no need to install it. We need to find out the IP address of the
virtual machine, so login using the VirtualBox window.

      1 - Type " ifconfig ". In "eth0" is "inet addr:". That's the IP address of your virtual
      machine.

      2 - On your Windows host, start "putty.exe". Type your IP address into the "Host Name" box.
      Type a name like "yacbuild" into the "Saved Sessions" box and click "Save". Click "Open" to
      start the SSH terminal. Click "Yes" to accept the ssh-rsa fingerprint.

      3 - Login to your virtual machine using the SSH terminal. Now you can resize your window,
      which you can't do in the VirtualBox window!

Section D - Install required packages

      1 - Type " sudo apt-get install git " and enter your password to install git.

      2 - Type " sudo apt-get install build-essential " to install compilers.

      3 - Type " sudo -k " to revoke your sudo password. You will not need sudo any more. Yes!

Section E - Build the OpenSSL Library

      1 - Type " cd " to get to the home directory

      2 - Type " wget http://www.openssl.org/source/openssl-1.0.1g.tar.gz " to get the exact version
      of openssl we need from the Internet.

      3 - Type " md5sum openssl-1.0.1g.tar.gz " and make sure you get
      66bf6f10f060d561929de96f9dfe5b8c

      4 - Type " tar xvzf openssl-1.0.1g.tar.gz " to extract the source files.

      5 - Type " cd openssl-1.0.1g "

      6 - Type " ./config "

      7 - Type " make "

Section F - Build the Berkeley DB library

      1 - Type " cd " to get to the home directory

      2 - Type " wget http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz "

      3 - Type " md5sum db-4.8.30.NC.tar.gz " and make sure you get a14a5486d6b4891d2434039a0ed4c5b7

      4 - Type " tar xvzf db-4.8.30.NC.tar.gz " to extract the source files

      5 - Type " cd db-4.8.30.NC/build_unix "

      6 - Type " ../dist/configure --disable-replication --enable-cxx "

      7 - Type " make "

Section G - Build the Boost library

      1 - Type " cd " to get to the home directory

      2 - Type " wget http://sourceforge.net/projects/boost/files/boost/1.54.0/boost_1_54_0.tar.gz "

      3 - Type " md5sum boost_1_54_0.tar.gz " and make sure you get efbfbff5a85a9330951f243d0a46e4b9

      4 - Type " tar xvzf boost_1_54_0.tar.gz " to extract the source files. It's a big one.

      5 - Type " cd  boost_1_54_0 "

      6 - Type " ./bootstrap.sh "

      7 - Type " ./b2 --with-chrono --with-filesystem --with-program_options --with-thread \
      --with-test stage "

Section H - Get the latest stable branch of the YACoin source

      1 - Type " cd " to get to the home directory

      2 - Type " git clone https://github.com/yacoin/yacoin " to get the YACoin source code.

      3 - Type " git tag -l " to see a list of stable branches.

      4 - Type " git checkout tags/stable_0.4.2 " to set your source files to the most recent
      stable branch.

Section I - Build the miniupnpc library

      1 - Type " cd " to get to the home directory

      2 - Type " wget http://miniupnp.free.fr/files/miniupnpc-1.8.tar.gz "

      3 - Type " md5sum miniupnpc-1.8.tar.gz " and make sure you get
      065bf20a20ebe605c675b7a5aaef340a

      4 - Type " tar xvzf miniupnpc-1.8.tar.gz "

      5 - Type " cd yacoin/src " miniupnpc is needed here

      6 - Type " ln -s ../../miniupnpc-1.8 miniupnpc " to make a symbolic link.

      7 - Type " cd miniupnpc "

      8 - Type " make "

Section J - Build YACoin (yacoind)

      1 - Type " cd " to get to the home directory

      2 - Type " cd yacoin/src"

      3 - Type " ln -s makefile.ubuntu makefile " to make a symbolic link to the ubuntu makefile

      4 - Type " make "

Section K - Get the yacoind executable file out of VirtualBox and running on a production
server.

      1 - Login to your server that you will use to run yacoind.

      2 - Type " sudo apt-get install openssh-server " if your server does not already have OpenSSH
      server installed.

      3 - Login to the VirtualBox virtual server you used to build yacoind.

      4 - Type " cd " to get to the home directory

      5 - Type " cd yacoin/src "

      6 - Type " scp yacoind yourusername@yourservername:. " to use SSH to copy the file onto your
      production server.

      7 - Go back to your production server.

      8 - Type " ./yacoind -server -daemon " to attempt to start the daemon for the first time

      9 - Follow the instructions to create your rpcuser and rpcpassword in .yacoin/yacoin.conf

      10 - Type " ./yacoind -server -daemon " to actually start the yacoind daemon

      11 - Type " tail -f .yacoin/debug.log " to watch the progress of yacoind. Hit CTRL-C to stop.

      12 - Type " ./yacoind getinfo " to see general info about the running daemon.

      13 - Type " ./yacoind --help " to see a list of commands you can use while the daemon is
      running.

      14 - Type " ./yacoind stop " when you need to stop the daemon.

Section L - Test YACoin (yacoind)

Many of the tests haven't been maintained and either don't compile or don't work properly. Remove the
tests that don't compile for now.

      1 - Login to the VirtualBox virtual machine you used to build yacoind.

      2 - Type " cd " to get to the home directory

      3 - Type " cd yacoin/src"

      4 - Type " rm test/Checkpoints_tests.cpp " because it doesn't compile

      5 - Type " rm test/miner_tests.cpp " because it doesn't compile

      6 - Type " rm test/wallet_tests.cpp " because it doesn't compile

      7 - Type " make test_yacoin "

      8 - Type " ./test_yacoin " to run the tests. Ouch! 110 failures detected! Now is your chance
          to contribute to YACoin by fixing the broken tests.

      9 - Type " git checkout test/Checkpoints_tests.cpp " to restore deleted test file.

      10 - Type " git checkout test/miner_tests.cpp " to restore deleted test file.

      11 - Type " git checkout test/wallet_tests.cpp " to restore deleted test file.

Section QT - Make a QT GUI version of YACoin
  
If you do all the above steps on Ubuntu 12.04 Desktop (instead of Server), you can also build the QT GUI 
version of YACoin.

      1 - Type " sudo apt-get install qt4-qmake libqt4-dev " to install QT development

      2 - Type " cd " to get to the home directory

      3 - Type " cd yacoin " 

      4 - Edit the file called yacoin-qt.pro and add the following lines near the top:

          BDB_INCLUDE_PATH=../db-4.8.30.NC/build_unix
          BDB_LIB_PATH=../db-4.8.30.NC/build_unix
          BOOST_INCLUDE_PATH=../boost_1_54_0
          BOOST_LIB_PATH=../boost_1_54_0/stage/lib
          OPENSSL_INCLUDE_PATH=../openssl-1.0.1g/include
          OPENSSL_LIB_PATH=../openssl-1.0.1g
          MINIUPNPC_INCLUDE_PATH=src
          MINIUPNPC_LIB_PATH=src/miniupnpc/
          # Uncomment for debug:
          #QMAKE_CXXFLAGS += -g
          #QMAKE_CFLAGS += -g
          #LIBS += -g

       5 - Type " qmake yacoin-qt.pro RELEASE=1 " to generate a Makefile. 

       6 - Type " make " to build yacoin-qt

       7 - Type " ./yacoin-qt & " to start YACoin QT GUI

Section CentOS 6.5:

A few minor changes will work on CentOS 6.5. It should work on RHEL and Fedora too. All the steps
are the same until you get to section QT above.

       1 - Instead of QT-1 above,
           Type " sudo yum install qt4-devel " to install QT development.

       2 - Do QT-2 through QT-4 above.

       3 - While you are editing yacoin-qt.pro also make these changes. First, find and delete the 
           line with -lrt in it.

           !windows:!macx {
                DEFINES += LINUX
                LIBS += -lrt               <----- Delete this line
           }
           Put these 3 lines before the last line of the file (the system line):
           
           !windows:!macx {
               LIBS += -lrt
           }

       3 - Instead of QT-5,
           Type " /usr/lib64/qt4/bin/qmake yacoin-qt.pro RELEASE=1 "

       4 - Type " make "

       5 - Type " ./yacoin-qt & " to start YACoin QT GUI


YACoin Official Development Tree.
---------------------------------------
Many thanks to WindMaster for initially setting up this repository to continue development and promotion of YACoin after the original
developer, GitHub user pocopoco, went paka paka. Due to community feedback and the need for an updated and stable client, this is now the official YACoin Development Tree. 

YACoin - a hybrid scrypt PoW + PoS based cryptocurrency forked from NovaCoin.

* Uses the scrypt + chacha20/8 (N,1,1) hashing algorithm.
* N increases over time to increase memory requirements.
* 1 minute PoW block targets.
* (?) minute PoS block targets.
* The PoW subsidy decreases as difficulty increases.
* Maximum PoW reward is 100 coins.

Development process
===========================

Developers work in their own trees, then submit pull requests when
they think their feature or bug fix is ready. For new features or
enhancements to YACoin, please submit pull requests to YACoin testing. 
Please refer to: https://help.github.com/articles/using-pull-requests
if you need any help.

The patch will be accepted if there is broad consensus that it is a
good thing.  Developers should expect to rework and resubmit patches
if they don't match the project's coding conventions (see coding.txt)
or are controversial.

The master branch (YACoin stable) is regularly built and tested, but is not guaranteed to be completely stable. 

From time to time a pull request will become outdated. If this occurs, and
the pull is no longer automatically mergeable; a comment on the pull will
be used to issue a warning of closure. The pull will be closed 15 days
after the warning if action is not taken by the author. Pull requests closed
in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after
15 days from their last activity. Issues closed in this manner will be 
labeled 'stale'.

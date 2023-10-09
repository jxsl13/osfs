# osfs

This is a package abstracting away the filesystem.
The main problem this package tries to tackle is to introduce permission handling for Windows. It is currently not possible to correctly handle Chown/Chmod permissions on Windows, as the functions os.Chown and os.Chmod work with integer uids and gids. Windows does not have integer ids but uses a string representation for their SIDs (S-0-1-2-3).

# References

- https://github.com/winfsp/winfsp (for future)
- https://github.com/christian-korneck/ownerly (chown)
- https://github.com/hectane/go-acl (chmod)
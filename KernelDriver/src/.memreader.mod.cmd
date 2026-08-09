savedcmd_memreader.mod := printf '%s\n'   memreader.o | awk '!x[$$0]++ { print("./"$$0) }' > memreader.mod
